"""PR #1 credential isolation regressions; never invoke real credential consumers."""
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from gaia_security.scanners import ScannerRunner

REPO='gaia-research/gaia-security'
ENV={'PATH':'/synthetic/tools','HOME':'/synthetic/home','SSL_CERT_FILE':'/synthetic/ca.pem',
     'GH_TOKEN':'dummy','GITHUB_TOKEN':'dummy','SEMGREP_APP_TOKEN':'dummy',
     'cloud_secret':'dummy','service_api_key':'dummy','DB_PASSWORD':'dummy',
     'SEMGREP_SEND_METRICS':'on','SEMGREP_ENABLE_VERSION_CHECK':'1'}

class EnvironmentTests(unittest.TestCase):
    def assert_isolated(self, calls):
        self.assertTrue(calls)
        for call in calls:
            env=call.kwargs['env']
            self.assertFalse(any(any(word in key.upper() for word in ('TOKEN','SECRET','API_KEY','PASSWORD')) for key in env))
            for key in ('PATH','HOME','SSL_CERT_FILE'):
                self.assertEqual(env[key],ENV[key])
            self.assertEqual(env['SEMGREP_SEND_METRICS'],'off')
            self.assertEqual(env['SEMGREP_ENABLE_VERSION_CHECK'],'0')
        self.assertEqual(dict(os.environ),ENV)

    def test_gitleaks_version_and_scan_isolated_on_all_outcomes(self):
        for outcome in ('clean','finding','failure','invalid','timeout','version_timeout'):
            with self.subTest(outcome=outcome),patch.dict(os.environ,ENV,clear=True),patch('shutil.which',return_value='/tool'):
                outputs=[]
                def run(cmd,**kwargs):
                    if cmd[1]=='version':
                        if outcome=='version_timeout':raise subprocess.TimeoutExpired(cmd,10)
                        return subprocess.CompletedProcess(cmd,0,'synthetic-version','')
                    out=Path(cmd[cmd.index('--report-path')+1]);outputs.append(out)
                    if outcome=='timeout':
                        out.write_text('private partial report')
                        raise subprocess.TimeoutExpired(cmd,300)
                    if outcome=='failure':return subprocess.CompletedProcess(cmd,7,'','private diagnostic')
                    if outcome=='invalid':out.write_text('{invalid')
                    else:
                        records=[] if outcome=='clean' else [{'RuleID':'synthetic','File':'fixture.txt','Secret':'redacted','StartLine':1}]
                        out.write_text(json.dumps(records))
                    return subprocess.CompletedProcess(cmd,0 if outcome=='clean' else 1,'','')
                with patch('subprocess.run',side_effect=run) as mocked:
                    status,records=ScannerRunner('.',REPO).run_gitleaks()
                self.assert_isolated(mocked.call_args_list)
                self.assertEqual(len(mocked.call_args_list),1 if outcome=='version_timeout' else 2)
                self.assertEqual(status.complete,outcome in ('clean','finding'))
                self.assertEqual(len(records),int(outcome=='finding'))
                for out in outputs:self.assertFalse(out.parent.exists())
                self.assertNotIn('private',status.notes)

    def test_common_adapter_uses_identical_environment_policy(self):
        with patch.dict(os.environ,ENV,clear=True),patch('shutil.which',return_value='/tool'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'{}','')) as mocked:
            ScannerRunner('.',REPO).run_trivy()
            self.assertEqual(len(mocked.call_args_list),2)
            self.assert_isolated(mocked.call_args_list)
