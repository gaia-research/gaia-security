"""Restricted workflow wrapper: preserve scanner failures and clean private output."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from gaia_security.registry import find_repo_root

@unittest.skipUnless(shutil.which('bash'),'Bash unavailable')
class RestrictedScanTests(unittest.TestCase):
    def test_success_failure_and_malformed_output_cleanup(self):
        root=find_repo_root()
        for case in ('success','failure','malformed'):
            with self.subTest(case=case),TemporaryDirectory() as tmp:
                work=Path(tmp);target=work/'target';target.mkdir()
                binary=work/'bin';binary.mkdir()
                stub=binary/'gitleaks'
                stub.write_text('#!'+sys.executable+'\n'+
                    'import json,os,sys\nfrom pathlib import Path\n'+
                    'if sys.argv[1]=="version":\n print("test-only")\n sys.exit(0)\n'+
                    'out=Path(sys.argv[sys.argv.index("--report-path")+1])\n'+
                    'case=os.environ["SMOKE_CASE"]\n'+
                    'out.write_text("{" if case=="malformed" else "[]")\n'+
                    'print("private-diagnostic-not-for-workflow-logs",file=sys.stderr)\n'+
                    'sys.exit(7 if case=="failure" else 0)\n')
                stub.chmod(0o700)
                env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],
                    RUNNER_TEMP=str(work),CALLER_REPO='gaia-research/gaia-security',SCANNERS='gitleaks',
                    GAIA_SECURITY_ROOT=str(root),PYTHONPATH=str(root/'src'),SMOKE_CASE=case)
                result=subprocess.run(['bash',str(root/'scripts/run-restricted-scan.sh'),str(target)],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0 if case=='success' else 2)
                self.assertFalse((work/'gaia-evidence').exists())
                lines=result.stdout.splitlines()
                self.assertEqual(lines[-1],'Restricted evidence cleanup verified')
                self.assertEqual(json.loads(lines[0])['complete'],case=='success')
                self.assertNotIn('private-diagnostic',result.stdout+result.stderr)

    def test_existing_evidence_not_taken_over_or_deleted(self):
        root=find_repo_root()
        with TemporaryDirectory() as tmp:
            work=Path(tmp);evidence=work/'gaia-evidence';evidence.mkdir()
            marker=evidence/'keep';marker.write_text('synthetic')
            env=dict(os.environ,RUNNER_TEMP=str(work),CALLER_REPO='gaia-research/gaia-security',SCANNERS='gitleaks',GAIA_SECURITY_ROOT=str(root))
            result=subprocess.run(['bash',str(root/'scripts/run-restricted-scan.sh'),str(work)],env=env,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertTrue(marker.exists())
