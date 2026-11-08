import unittest
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from gaia_security.registry import find_repo_root,load_dispositions,load_repositories,validate_all_profiles
from gaia_security.posture import inspect_repository_posture

class RegistryTests(unittest.TestCase):
    def test_registry_uses_governance_not_target(self):
        with TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'registry').mkdir();(p/'registry/dispositions.json').write_text('{"dispositions":[{"evil":true}]}')
            self.assertNotEqual(find_repo_root(p),p)
            self.assertEqual(load_dispositions(p)['dispositions'],[])
    def test_missing_governance_fails_closed(self):
        with TemporaryDirectory() as tmp, patch.dict(os.environ,{'GAIA_SECURITY_ROOT':tmp}):
            with self.assertRaises(ValueError):load_dispositions()
    def test_profiles_required(self):
        self.assertTrue(validate_all_profiles()['all_valid'])
        with TemporaryDirectory() as tmp:
            self.assertFalse(validate_all_profiles(Path(tmp))['all_valid'])
    def test_default_setup_without_yaml(self):
        with TemporaryDirectory() as tmp:
            p=inspect_repository_posture(tmp,'gaia-research/example',api_override_data={'codeql_default_setup_configured':True})
            self.assertTrue(p.codeql_effective)
            self.assertFalse(p.codeql_workflow_present)
    def test_unqueried_setup_unknown(self):
        with TemporaryDirectory() as tmp:
            p=inspect_repository_posture(tmp,'gaia-research/example')
            self.assertIsNone(p.codeql_effective)
            self.assertIsNone(p.codeql_default_setup_configured)
    def test_api_error_unknown_not_disabled(self):
        with TemporaryDirectory() as tmp,patch('gaia_security.posture._run_gh_api',return_value=(1,None)):
            self.assertIsNone(inspect_repository_posture(tmp,'gaia-research/example',True).codeql_effective)
