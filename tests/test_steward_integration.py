import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from gaia_security.cli import main,private_write
from gaia_security.models import ScannerStatus
from gaia_security.pipeline import validate_finding,plan_remediation
from gaia_security.reporting import to_report_dict
from gaia_security.registry import find_repo_root,load_repositories
from gaia_security.steward import generate_steward_dispatch_payloads
from test_pipeline import candidate,approved

class StewardTests(unittest.TestCase):
    def test_pending_findings_not_exported(self):
        f=candidate()
        self.assertEqual(generate_steward_dispatch_payloads([f],f.repository),[])
    def test_proposals_have_full_traceability_and_no_authority(self):
        f=candidate()
        f.validation=validate_finding(f,approved(f),source_commit='a'*40)
        f.remediation=plan_remediation(f,f.validation)
        packets=generate_steward_dispatch_payloads([f],f.repository)
        self.assertEqual(len(packets),1)
        p=packets[0]
        self.assertEqual(p['integration_pr_limit'],1)
        self.assertEqual(p['authorization_status'],'requires_human_or_lead_approval')
        self.assertTrue(p['items'][0]['evidence_refs'])
        self.assertTrue(p['items'][0]['validation_summary']['disposition_id'])
        self.assertTrue(p['items'][0]['verification_contract']['verification_steps'])
    def test_output_owner_only_no_overwrite(self):
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.json';private_write(p,'{}')
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError): private_write(p,'replaced')
    def test_report_schema_and_registry(self):
        try:
            from jsonschema import Draft202012Validator
            from referencing import Registry,Resource
        except ImportError:
            self.skipTest('Development-only jsonschema missing')
        root=find_repo_root()
        resources=[]
        for p in (root/'schemas').glob('*.json'):
            data=json.loads(p.read_text());Draft202012Validator.check_schema(data)
            resources.append((data['$id'],Resource.from_contents(data)))
        registry=Registry().with_resources(resources)
        def validate(file,data):
            schema=json.loads((root/'schemas'/file).read_text())
            Draft202012Validator(schema,registry=registry).validate(data)
        f=candidate();f.validation=validate_finding(f);f.remediation=plan_remediation(f,f.validation)
        validate('finding.schema.json',f.to_dict())
        validate('scan-report.schema.json',to_report_dict([f],[ScannerStatus('semgrep-ce')],repository=f.repository))
        validate('repository-registry.schema.json',load_repositories())
        f.validation=validate_finding(f,approved(f),source_commit='a'*40)
        validate('steward-handoff.schema.json',generate_steward_dispatch_payloads([f],f.repository))
    def test_cli_config_and_selftest(self):
        self.assertEqual(main(['validate-configs']),0)
        self.assertEqual(main(['selftest']),0)
    def test_workflow_yaml(self):
        try: import yaml
        except ImportError: self.skipTest('Development-only PyYAML missing')
        for p in (find_repo_root()/'.github/workflows').glob('*.yml'):
            data=yaml.safe_load(p.read_text());self.assertIn('jobs',data)
        manual=(find_repo_root()/'.github/workflows/manual-comprehensive-scan.yml').read_text()
        self.assertNotIn('|| true',manual)
        self.assertNotIn('upload-artifact',manual)
