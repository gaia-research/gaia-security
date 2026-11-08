"""gaia-sec: explicitly invoked scanners, conservative triage, restricted outputs."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from gaia_security.models import EvidenceRecord, NormalizedFinding
from gaia_security.pipeline import SecurityPipeline, validate_finding
from gaia_security.posture import inspect_repository_posture
from gaia_security.registry import load_repositories, validate_all_profiles, find_repo_root
from gaia_security.schema import validate_instance
import re
from gaia_security.reporting import to_report_dict, render_markdown_report
from gaia_security.redaction import redact_structure, redact_text
from gaia_security.scanners import ScannerRunner, deduplicate_evidences
from gaia_security.steward import generate_steward_dispatch_payloads

SCANNERS = ('gitleaks','osv-scanner','trivy','semgrep-ce')

def private_write(path, content):
    # Refuse overwrites/symlinks and create owner-only output atomically.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd,'w') as out:
        out.write(content)


def cmd_validate_configs(args):
    data = validate_all_profiles()
    print(json.dumps(data,indent=2))
    return 0 if data['all_valid'] else 2


def cmd_discover(args):
    print(json.dumps(load_repositories(),indent=2))
    return 0


def cmd_inspect_posture(args):
    print(json.dumps(inspect_repository_posture(args.path,args.repo,args.github_api).to_dict(),indent=2))
    return 0


def cmd_scan(args):
    path = Path(args.path).resolve(strict=True)
    names = list(SCANNERS) if args.scanners == 'all' else args.scanners.split(',')
    if not names or len(set(names)) != len(names) or set(names)-set(SCANNERS):
        raise ValueError('Unknown or duplicate scanner selection')
    runner = ScannerRunner(path,args.repo)
    statuses, evidence = [], []
    methods = {'gitleaks':runner.run_gitleaks,'osv-scanner':runner.run_osv_scanner,'trivy':runner.run_trivy,'semgrep-ce':runner.run_semgrep}
    for name in names:
        status, records = methods[name]()
        statuses.append(status)
        evidence.extend(records)
    if args.include_github_api:
        sts, records = runner.ingest_github_api_alerts()
        statuses.extend(sts)
        evidence.extend(records)
    pipeline = SecurityPipeline(args.repo,path)
    findings = pipeline.process_findings(deduplicate_evidences(args.repo,evidence))
    posture = inspect_repository_posture(path,args.repo,args.include_github_api)
    report = to_report_dict(findings,statuses,posture,args.repo,len(evidence),metadata={'source_commit':pipeline.source_commit,'governance_root':str(runner.repo_root)})
    if args.output_json: private_write(args.output_json,json.dumps(report,indent=2)+'\n')
    if args.output_md: private_write(args.output_md,render_markdown_report(report))
    # Default terminal receipt is counts only. Detailed reports remain owner-only.
    print(json.dumps({'repository':args.repo,'findings':len(findings),'pending_validation':report['summary']['pending_validation'],
        'complete':report['complete'],'scanners':[{'name':s.scanner,'complete':s.complete,'exit_code':s.exit_code} for s in statuses]}))
    return 0 if report['complete'] else 2


def cmd_steward_export(args):
    report = json.loads(Path(args.input_report).read_text())
    schemas = find_repo_root() / 'schemas'
    validate_instance(report,json.loads((schemas/'scan-report.schema.json').read_text()),schemas)
    pipeline = SecurityPipeline(report['repository'],args.path)
    source_commit = report['metadata'].get('source_commit')
    if not source_commit or source_commit != pipeline.source_commit:
        raise ValueError('Report revision must equal the clean checkout revision')
    remote = subprocess.run(['git','-C',str(pipeline.target_path),'remote','get-url','origin'],capture_output=True,text=True)
    url = remote.stdout.strip().removesuffix('.git')
    match = re.fullmatch(r'(?:https://github.com/|git@github.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)',url)
    if remote.returncode or not match or match.group(1) != report['repository']:
        raise ValueError('Report repository must equal checkout origin identity')
    canonical = []
    for supplied in report['findings']:
        if supplied['repository'] != report['repository']:
            raise ValueError('Finding repository mismatch')
        records = [EvidenceRecord.from_dict(e) for e in supplied['evidences']]
        reconstructed = deduplicate_evidences(report['repository'],records)
        if len(reconstructed) != 1:
            raise ValueError('Finding evidence must reconstruct one canonical finding')
        finding = reconstructed[0]
        for key in ('finding_id','repository','category','title','raw_severity','primary_file','primary_line'):
            if supplied[key] != getattr(finding,key):
                raise ValueError('Finding canonical identity mismatch')
        canonical.append(finding)
    # Re-evaluate exact revision AND evidence digest against trusted reviews.
    findings = pipeline.process_findings(canonical)
    packets = generate_steward_dispatch_payloads(findings,report['repository'])
    data = json.dumps(redact_structure(packets),indent=2)+'\n'
    if args.output: private_write(args.output,data)
    else: print(data)
    return 0


def cmd_selftest(args):
    # Small assertions; full regression suite lives in tests/.
    token = 'ghp_'+'x'*36
    assert token not in redact_text(token)
    e = EvidenceRecord('semgrep-ce','example','high','tests/example.py',1)
    f = deduplicate_evidences('gaia-research/gaia-security',[e])[0]
    assert validate_finding(f).is_reachable is None
    assert validate_finding(f).disposition == 'pending_validation'
    assert not generate_steward_dispatch_payloads([f],f.repository)
    print('Synthetic redaction, conservative validation and non-authorization selftest passed')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='gaia-sec')
    subs = parser.add_subparsers(dest='command',required=True)
    for name,func in [('discover',cmd_discover),('validate-configs',cmd_validate_configs),('selftest',cmd_selftest)]:
        subs.add_parser(name).set_defaults(func=func)
    p = subs.add_parser('inspect-posture'); p.set_defaults(func=cmd_inspect_posture)
    p.add_argument('--repo',required=True); p.add_argument('--path',default='.')
    p.add_argument('--github-api',action='store_true')
    p = subs.add_parser('scan'); p.set_defaults(func=cmd_scan)
    p.add_argument('--repo',required=True); p.add_argument('--path',required=True)
    p.add_argument('--scanners',default='all'); p.add_argument('--include-github-api',action='store_true')
    p.add_argument('--output-json'); p.add_argument('--output-md')
    p = subs.add_parser('steward-export'); p.set_defaults(func=cmd_steward_export)
    p.add_argument('--input-report',required=True); p.add_argument('--path',required=True)
    p.add_argument('--output')
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError, KeyError) as exc:
        print('Error: '+redact_text(str(exc)),file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
