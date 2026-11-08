"""Regression cases from independent review; all inputs are offline synthetic fixtures."""
import copy
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from gaia_security.cli import main
from gaia_security.contracts import validate_native, evidence_digest
from gaia_security.models import EvidenceRecord, ScannerStatus
from gaia_security.pipeline import validate_finding, plan_remediation
from gaia_security.reporting import to_report_dict
from gaia_security.scanners import ScannerRunner, deduplicate_evidences
from test_pipeline import candidate,approved

class BoundaryRegressionTests(unittest.TestCase):
    def test_empty_object_scanner_results_never_clean(self):
        for method in ('run_osv_scanner','run_semgrep','run_trivy'):
            with self.subTest(method=method),patch('shutil.which',return_value='/native'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'{}','')):
                status,records=getattr(ScannerRunner('.','gaia-research/gaia-security'),method)()
                self.assertFalse(status.complete)
                self.assertEqual(records,[])
    def test_empty_object_github_pages_not_clean(self):
        with patch('shutil.which',return_value='/gh'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,'{}','')):
            statuses,records=ScannerRunner('.','gaia-research/gaia-security').ingest_github_api_alerts()
        self.assertFalse(any(s.complete for s in statuses))
    def test_malformed_nested_records_rejected(self):
        cases=[('gitleaks',[{}]),('semgrep-ce',{'results':[{}],'errors':[]}),
            ('osv-scanner',{'results':[{'source':{},'packages':[]}]}),
            ('trivy',{'SchemaVersion':2,'ArtifactName':'test','ArtifactType':'repository','Metadata':{},'Results':{}}),
            ('codeql-alerts',[{'state':'open'}])]
        for name,data in cases:
            with self.subTest(name=name),self.assertRaises((ValueError,KeyError,TypeError)):
                validate_native(name,data)
    def test_unknown_alert_states_incomplete_for_both_native_apis(self):
        examples={
            'codeql':{'state':'unexpected','rule':{'id':'synthetic'},'most_recent_instance':{'location':{'path':'synthetic.py','start_line':1}}},
            'dependabot':{'state':'unexpected','security_advisory':{'ghsa_id':'GHSA-SYNTHETIC'},'dependency':{'manifest_path':'package-lock.json','package':{'name':'synthetic','ecosystem':'npm'}}}}
        for name,item in examples.items():
            with self.subTest(name=name):
                statuses,records=ScannerRunner('.','gaia-research/gaia-security').ingest_github_api_alerts({name:[item]})
                self.assertFalse(next(s for s in statuses if s.scanner==name).complete)
                self.assertEqual(records,[])
                with patch('shutil.which',return_value='/gh'),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps([[item]]),'')):
                    statuses,records=ScannerRunner('.','gaia-research/gaia-security').ingest_github_api_alerts()
                self.assertFalse(any(s.complete for s in statuses))

    def test_known_closed_states_are_valid_but_not_open_findings(self):
        item={'state':'fixed','security_advisory':{'ghsa_id':'GHSA-SYNTHETIC'},'dependency':{'manifest_path':'package-lock.json','package':{'name':'synthetic','ecosystem':'npm'}}}
        statuses,records=ScannerRunner('.','gaia-research/gaia-security').ingest_github_api_alerts({'dependabot':[item]})
        self.assertTrue(all(s.complete for s in statuses))
        self.assertEqual(records,[])

    def test_valid_native_empty_envelopes(self):
        validate_native('gitleaks',[])
        validate_native('semgrep-ce',{'results':[],'errors':[]})
        validate_native('osv-scanner',{'results':[]})
        validate_native('trivy',{'SchemaVersion':2,'ArtifactName':'test','ArtifactType':'repository','Metadata':{}})
    def test_invalid_review_stays_pending(self):
        f=candidate()
        variants=[('disposition','made_up_suppression'),('existing_mitigations','not-a-list'),('duplicate_of',123),('validated_priority','UNKNOWN')]
        for field,value in variants:
            data=approved(f);data['dispositions'][0]['validation'][field]=value
            self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'pending_validation')
        data=approved(f);data['dispositions'][0]['expires_at']='2099-01-01T00:00:00'
        self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'pending_validation')
    def test_changed_evidence_not_reviewed(self):
        f=candidate();data=approved(f)
        f.evidences[0].message='Changed contextual evidence'
        self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'pending_validation')
    def test_ecosystem_identity_and_unknown_bridge(self):
        records=[EvidenceRecord('osv-scanner','GHSA-SYNTHETIC','high','manifest',1,advisory_ids=['GHSA-SYNTHETIC'],package_name='pkg',package_version='1',ecosystem=e) for e in ('npm','PyPI',None)]
        findings=deduplicate_evidences('gaia-research/gaia-security',records)
        self.assertEqual(len(findings),3)
        self.assertEqual(len({f.finding_id for f in findings}),3)
        self.assertEqual([f.to_dict() for f in findings],[f.to_dict() for f in deduplicate_evidences('gaia-research/gaia-security',list(reversed(records)))])
        data=approved(findings[0])
        self.assertEqual(sum(validate_finding(f,data,source_commit='a'*40).disposition=='action_required' for f in findings),1)
    def test_unknown_version_cannot_bridge_two_versions(self):
        records=[EvidenceRecord('osv-scanner','GHSA-SYNTHETIC','high','manifest',1,advisory_ids=['GHSA-SYNTHETIC'],package_name='pkg',package_version=v,ecosystem='npm') for v in ('1','2',None)]
        self.assertEqual(len(deduplicate_evidences('gaia-research/gaia-security',records)),3)
    def test_export_binds_revision_identity_evidence_and_repository(self):
        f=candidate(); review=approved(f)
        def process(findings):
            for item in findings:
                item.validation=validate_finding(item,review,source_commit='a'*40)
                item.remediation=plan_remediation(item,item.validation)
            return findings
        with TemporaryDirectory() as tmp:
            fake=SimpleNamespace(source_commit='a'*40,target_path=Path(tmp),process_findings=process)
            original=to_report_dict([f],[ScannerStatus('semgrep-ce')],repository=f.repository,metadata={'source_commit':'a'*40})
            for variant in ('valid','revision','category','evidence','repository','identity'):
                report=copy.deepcopy(original)
                if variant=='revision':report['metadata']['source_commit']='b'*40
                if variant=='category':report['findings'][0]['category']='secret'
                if variant=='evidence':report['findings'][0]['evidences'][0]['message']='Unreviewed evidence'
                if variant=='repository':report['findings'][0]['repository']='other/security'
                if variant=='identity':report['findings'][0]['finding_id']='GSEC-'+'0'*12
                source=Path(tmp)/(variant+'.json');source.write_text(json.dumps(report))
                output=Path(tmp)/(variant+'-export.json')
                with patch('gaia_security.cli.SecurityPipeline',return_value=fake),patch('gaia_security.cli.subprocess.run',return_value=subprocess.CompletedProcess([],0,'https://github.com/'+f.repository+'.git\n','')):
                    code=main(['steward-export','--input-report',str(source),'--path',tmp,'--output',str(output)])
                if variant=='valid':
                    self.assertEqual(code,0);self.assertEqual(len(json.loads(output.read_text())),1)
                elif variant=='evidence':
                    self.assertEqual(code,0);self.assertEqual(json.loads(output.read_text()),[])
                else:
                    self.assertEqual(code,2);self.assertFalse(output.exists())
