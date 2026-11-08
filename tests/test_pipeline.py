import unittest
from gaia_security.models import EvidenceRecord
from gaia_security.scanners import deduplicate_evidences
from gaia_security.pipeline import validate_finding, plan_remediation
from gaia_security.contracts import evidence_digest

REPO='gaia-research/gaia-security'
def candidate(path='src/server.py',scanner='semgrep-ce'):
    return deduplicate_evidences(REPO,[EvidenceRecord(scanner,'example','high',path,1)])[0]

def approved(f):
    return {'dispositions':[{'repository':f.repository,'finding_id':f.finding_id,
      'source_commit':'a'*40,'expires_at':'2099-01-01T00:00:00Z','reviewer':'test-reviewer',
      'disposition_id':'SYNTHETIC-REVIEW','evidence_refs':['private:synthetic-fixture'],
      'evidence_sha256':evidence_digest(f.evidences),
      'validation':{'is_genuine':True,'is_reachable':True,'boundary_crossed':True,
        'exploitation_plausible':True,'existing_mitigations':[],'duplicate_of':None,
        'disposition':'action_required','validated_priority':'P1','confidence':'high',
        'rationale':'Synthetic reviewed test case'}}]}

class PipelineTests(unittest.TestCase):
    def test_no_inferred_exploitation_or_safety(self):
        for path in ['src/server.py','tests/secrets.py','packages/core/test/fixtures/a.ts','.github/skills/a.py']:
            f=candidate(path)
            v=validate_finding(f,{'dispositions':[]})
            self.assertEqual(v.disposition,'pending_validation')
            self.assertIsNone(v.is_genuine)
            self.assertIsNone(v.is_reachable)
            self.assertIsNone(v.boundary_crossed)
            self.assertIsNone(v.exploitation_plausible)
            self.assertEqual(v.validated_priority,'UNASSESSED')
    def test_zero_dependency_repo_not_automatically_safe(self):
        f=candidate('package-lock.json','osv-scanner')
        self.assertEqual(validate_finding(f,{'dispositions':[]}).disposition,'pending_validation')
    def test_exact_revision_and_evidence_required(self):
        f=candidate(); data=approved(f)
        self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'action_required')
        self.assertEqual(validate_finding(f,data,source_commit='b'*40).disposition,'pending_validation')
        data['dispositions'][0]['reviewer']=''
        self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'pending_validation')
    def test_wrong_repo_expiry_or_missing_answers_fail_closed(self):
        f=candidate()
        for key,value in [('repository','other/gaia-security'),('expires_at','2000-01-01T00:00:00Z'),('evidence_refs',[])]:
            data=approved(f);data['dispositions'][0][key]=value
            self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'pending_validation')
        data=approved(f);del data['dispositions'][0]['validation']['boundary_crossed']
        self.assertEqual(validate_finding(f,data,source_commit='a'*40).disposition,'pending_validation')
    def test_no_auto_authorization(self):
        f=candidate()
        plan=plan_remediation(f,validate_finding(f))
        self.assertEqual(plan.authorization_status,'requires_human_or_lead_approval')
        self.assertIn('Investigate',plan.recommended_action)
    def test_serialization_roundtrip_preserves_unknown(self):
        f=candidate()
        from gaia_security.models import NormalizedFinding
        self.assertEqual(NormalizedFinding.from_dict(f.to_dict()).to_dict(),f.to_dict())
