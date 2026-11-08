import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from gaia_security.scanners import ScannerRunner,deduplicate_evidences,parse_osv,parse_github
from gaia_security.models import EvidenceRecord

REPO='gaia-research/gaia-security'
class ScannerTests(unittest.TestCase):
    def test_osv_v2_source_and_package_identity(self):
        raw={'results':[{'source':{'path':'/target/package-lock.json'},'packages':[{'package':{'name':'pkg','version':'1.0.0','ecosystem':'npm'},'vulnerabilities':[{'id':'GHSA-example','aliases':['CVE-TEST'],'database_specific':{'severity':'HIGH'}}]}]}]}
        e=parse_osv(raw,Path('/target'))[0]
        self.assertEqual((e.file_path,e.package_name,e.package_version,e.raw_severity),('package-lock.json','pkg','1.0.0','high'))
    def test_alias_dedup_and_distinct_package_and_version(self):
        ev=lambda name,version,rule,ids: EvidenceRecord('osv-scanner',rule,'high','package-lock.json',1,advisory_ids=ids,package_name=name,package_version=version)
        records=[ev('a','1','CVE-TEST',['CVE-TEST']),ev('a','1','GHSA-TEST',['CVE-TEST','GHSA-TEST']),ev('b','1','CVE-TEST',['CVE-TEST']),ev('a','2','CVE-TEST',['CVE-TEST'])]
        findings=deduplicate_evidences(REPO,records)
        self.assertEqual(len(findings),3)
        self.assertEqual(len({f.finding_id for f in findings}),3)
        self.assertEqual([f.to_dict() for f in findings],[f.to_dict() for f in deduplicate_evidences(REPO,list(reversed(records)))])
    def test_closed_alerts_not_ingested(self):
        self.assertEqual(parse_github('dependabot',[{'state':'fixed','dependency':{'manifest_path':'package-lock.json','package':{'name':'synthetic','ecosystem':'npm'}},'security_advisory':{'ghsa_id':'GHSA-TEST'}}]),[])
    def test_missing_semgrep_not_substituted(self):
        with patch('shutil.which',return_value=None):
            status,evidence=ScannerRunner('.',REPO).run_semgrep()
        self.assertFalse(status.executed)
        self.assertFalse(status.config_validated)
        self.assertFalse(status.complete)
        self.assertEqual(evidence,[])
    def test_native_failure_not_clean(self):
        with patch('shutil.which',return_value='/tool'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],2,'','private diagnostic')):
            status,e=ScannerRunner('.',REPO).run_trivy()
        self.assertFalse(status.complete)
        self.assertNotIn('private diagnostic',status.notes)
        self.assertEqual(e,[])
    def test_invalid_json_not_clean(self):
        with patch('shutil.which',return_value='/tool'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'{invalid','')):
            status,e=ScannerRunner('.',REPO).run_trivy()
        self.assertFalse(status.complete)
    def test_paginated_open_github_query(self):
        runner=ScannerRunner('.',REPO)
        with patch('shutil.which',return_value='/gh'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'[[],[]]','')) as run:
            statuses,records=runner.ingest_github_api_alerts()
        self.assertTrue(all(s.complete for s in statuses))
        self.assertTrue(all(not s.executed for s in statuses))
        self.assertIn('--paginate',run.call_args.args[0])
        self.assertIn('state=open',run.call_args.args[0][-1])
    def test_api_denial_incomplete(self):
        with patch('shutil.which',return_value='/gh'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],1,'','denied')):
            statuses,e=ScannerRunner('.',REPO).ingest_github_api_alerts()
        self.assertFalse(any(s.complete for s in statuses))
