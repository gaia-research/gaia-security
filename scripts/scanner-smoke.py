#!/usr/bin/env python3
"""Opt-in Linux native scanner validation. Synthetic inputs are never executed.

Only static counts/check names are printed. Detailed reports stay in owner-only
scratch space and are removed even when a check fails. No GitHub API access.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

REPO='gaia-research/gaia-security'
TOOLS=('gitleaks','osv-scanner','trivy','semgrep-ce')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def invoke(command, env, expected):
    result=subprocess.run(command,capture_output=True,text=True,env=env,timeout=360)
    require(result.returncode==expected,'Unexpected smoke command exit status')
    return result


@contextmanager
def restricted_scratch(runner_temp):
    # Keep ALL smoke reports under the same always-cleaned workflow root,
    # including when the Python process is cancelled before finally can run.
    evidence=runner_temp/'gaia-evidence'
    evidence.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='smoke-',dir=evidence) as temporary:
            yield Path(temporary)
    finally:
        shutil.rmtree(evidence)


def validate():
    require(sys.platform=='linux','Native smoke requires Linux')
    root=Path(os.environ['GAIA_SECURITY_ROOT']).resolve()
    runner_temp=Path(os.environ['RUNNER_TEMP']).resolve()
    for binary in ('gitleaks','osv-scanner','trivy','semgrep','git','bash'):
        require(shutil.which(binary) is not None,'Required native smoke tool unavailable')
    with restricted_scratch(runner_temp) as scratch:
        require(stat.S_IMODE(scratch.stat().st_mode)==0o700,'Scratch permissions not restricted')
        native_tmp=scratch/'native-tmp';native_tmp.mkdir(mode=0o700)
        env=dict(os.environ,PYTHONPATH=str(root/'src'),TMPDIR=str(native_tmp))
        positive=scratch/'positive';negative=scratch/'negative'
        positive.mkdir(mode=0o700);negative.mkdir(mode=0o700)
        # Dummy credentials, vulnerable source and manifests are parsed only.
        dummy=hashlib.sha256(b'gaia-native-smoke-dummy-not-a-credential').hexdigest()
        (positive/'credential.txt').write_text('gaia_mcp_key = '+repr(dummy)+'\n')
        (negative/'credential.txt').write_text('gaia_mcp_key = "short-placeholder"\n')
        (positive/'patterns.py').write_text('import pickle\nimport subprocess\npickle.loads(payload)\nsubprocess.run(command, shell=True)\n')
        (negative/'patterns.py').write_text('import json\nimport subprocess\njson.loads(payload)\nsubprocess.run(["echo", "safe"], shell=False)\n')
        (positive/'requirements.txt').write_text('urllib3==1.26.0\n')
        # Use a real resolvable, pinned advisory-negative package. Nonexistent
        # packages cause a native resolution failure, not a clean negative.
        # A future advisory should fail this smoke check, not be suppressed.
        (negative/'requirements.txt').write_text('six==1.17.0\n')
        docker='FROM scratch\nUSER {user}\nHEALTHCHECK CMD ["/bin/true"]\n'
        (positive/'Dockerfile').write_text(docker.format(user='root'))
        (negative/'Dockerfile').write_text(docker.format(user='65532:65532'))
        for scanner in TOOLS:
            for label,target in (('positive',positive),('negative',negative)):
                report=scratch/(scanner+'-'+label+'.json')
                markdown=report.with_suffix('.md')
                result=invoke([sys.executable,'-m','gaia_security','scan','--repo',REPO,'--path',str(target),'--scanners',scanner,'--output-json',str(report),'--output-md',str(markdown)],env,0)
                receipt=json.loads(result.stdout)
                data=json.loads(report.read_text())
                require(receipt['complete'] and data['complete'],'Native smoke scan incomplete')
                status=data['scanners_telemetry'][0]
                require(status['executed'] and status['complete'] and status['config_validated'],'Native tool not executed/validated')
                require(bool(data['findings'])==(label=='positive'),'Positive/negative fixture result mismatch')
                records=[e for finding in data['findings'] for e in finding['evidences']]
                if label=='positive':
                    if scanner=='gitleaks':require(any(e['rule_id']=='gaia-mcp-bearer-token' for e in records),'Custom token fixture not found')
                    if scanner=='osv-scanner':require(any(e['package_name']=='urllib3' for e in records),'Dependency fixture not found')
                    if scanner=='trivy':require(any(e['rule_id']=='DS-0002' for e in records),'Root-user fixture not found')
                    if scanner=='semgrep-ce':
                        for rule in ('gaia.python.unsafe-pickle-deserialization','gaia.python.subprocess-shell-true'):
                            require(any(e['rule_id'].endswith(rule) for e in records),'SAST fixture not found')
                for path in (report,markdown):require(stat.S_IMODE(path.stat().st_mode)==0o600,'Evidence permissions not restricted')
                require(dummy not in result.stdout and dummy not in result.stderr,'Dummy credential reached terminal output')
                require(not list(native_tmp.glob('gaia-sec-*')),'Gitleaks temporary evidence not removed')
                print(json.dumps({'check':'native-fixture','scanner':scanner,'case':label,'complete':True,'findings':len(data['findings'])}))
        # A real native parser error, not just an unavailable/fake executable,
        # must propagate incomplete coverage through the public CLI.
        partial=scratch/'partial';partial.mkdir(mode=0o700)
        (partial/'valid.py').write_text((positive/'patterns.py').read_text())
        (partial/'broken.py').write_text('def unfinished(\n')
        partial_report=scratch/'partial.json'
        result=invoke([sys.executable,'-m','gaia_security','scan','--repo',REPO,'--path',str(partial),'--scanners','semgrep-ce','--output-json',str(partial_report)],env,2)
        data=json.loads(partial_report.read_text())
        status=data['scanners_telemetry'][0]
        require(not data['complete'] and status['executed'] and not status['complete'],'Native parser error incorrectly marked clean')
        require(stat.S_IMODE(partial_report.stat().st_mode)==0o600,'Partial evidence permissions not restricted')
        print(json.dumps({'check':'native-incomplete','scanner':'semgrep-ce','exit_code':2,'native_exit':status['exit_code'],'complete':False}))
        # Exercise the SAME shell wrapper as the reusable workflow. Missing,
        # failing and malformed scanners must preserve exit 2 and delete both
        # detailed reports and raw scanner temporaries, not produce clean scans.
        isolated=scratch/'isolated-bin';isolated.mkdir(mode=0o700)
        for binary in ('python3','git','bash','mkdir','rm'):
            (isolated/binary).symlink_to(shutil.which(binary))
        fake=isolated/'semgrep'
        for case in ('success','missing','failure','malformed'):
            work=scratch/('wrapper-'+case);work.mkdir(mode=0o700)
            isolated_env=dict(env,RUNNER_TEMP=str(work),CALLER_REPO=REPO,SCANNERS='gitleaks')
            if case!='success':
                isolated_env.update(PATH=str(isolated),SCANNERS='semgrep-ce')
                if case!='missing':
                    fake.write_text('#!/bin/bash\n'+('exit 7\n' if case=='failure' else "printf '{}\\n'\n"))
                    fake.chmod(0o700)
            result=invoke(['bash',str(root/'scripts/run-restricted-scan.sh'),str(negative)],isolated_env,0 if case=='success' else 2)
            lines=result.stdout.splitlines()
            require(lines[-1]=='Restricted evidence cleanup verified','Wrapper cleanup receipt absent')
            receipt=json.loads(lines[0])
            require(receipt['complete']==(case=='success'),'Incomplete scan incorrectly marked clean')
            if case!='success':
                expected={'missing':None,'failure':7,'malformed':0}[case]
                require(receipt['scanners'][0]['exit_code']==expected,'Incomplete failure telemetry mismatch')
            require(not (work/'gaia-evidence').exists(),'Workflow evidence cleanup failed')
            print(json.dumps({'check':'restricted-wrapper','case':case,'exit_code':result.returncode,'cleanup':True}))
    require(not scratch.exists() and not (runner_temp/'gaia-evidence').exists(),'Synthetic smoke evidence cleanup failed')
    print(json.dumps({'check':'smoke-scratch-cleanup','removed':True}))


if __name__=='__main__':
    try:
        validate()
    except RuntimeError as error:
        # require() uses only fixed, developer-authored messages, never findings.
        print('Native scanner smoke failed: '+str(error),file=sys.stderr)
        sys.exit(2)
    except Exception:
        # Never print subprocess stderr, assertion payloads or private reports.
        print('Native scanner smoke failed; no private evidence published',file=sys.stderr)
        sys.exit(2)
