"""Stage B consumes explicit review evidence, never guesses reachability from paths."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import subprocess
from gaia_security.models import NormalizedFinding, ValidationAssessment, RemediationPlan
from gaia_security.registry import load_dispositions, load_repositories
from gaia_security.contracts import evidence_digest, validate_disposition


def validate_finding(finding: NormalizedFinding, dispositions_data=None, repositories_data=None,
                     source_commit: str | None = None) -> ValidationAssessment:
    data = load_dispositions() if dispositions_data is None else dispositions_data
    for entry in data.get('dispositions', []):
        # Exact identities and reviewed source revision, never path-based blanket exclusions.
        if entry.get('repository') != finding.repository or entry.get('finding_id') != finding.finding_id:
            continue
        if not source_commit or entry.get('source_commit') != source_commit:
            continue
        try:
            expires = validate_disposition(entry)
            if entry['evidence_sha256'] != evidence_digest(finding.evidences):
                continue
            if expires <= datetime.now(timezone.utc):
                continue
            assessment = entry['validation']
            questions = ('is_genuine', 'is_reachable', 'boundary_crossed', 'exploitation_plausible')
            if not entry.get('reviewer') or not entry.get('evidence_refs'):
                continue
            if any(type(assessment.get(q)) is not bool for q in questions):
                continue
            if not assessment.get('rationale') or 'existing_mitigations' not in assessment or 'duplicate_of' not in assessment:
                continue
            result = ValidationAssessment.from_dict(assessment)
            result.disposition_id = entry['disposition_id']
            return result
        except (KeyError, TypeError, ValueError):
            continue
    return ValidationAssessment(rationale='Unvalidated detection. Fixture paths, devDependency labels and scanner agreement do not establish safety, reachability or exploitation.')


def plan_remediation(finding, validation, default_branch='main') -> RemediationPlan:
    if validation.disposition == 'pending_validation':
        action = 'Investigate all six validation questions; preserve restricted evidence. No repair authorized.'
    elif finding.category == 'secret':
        action = 'Ask the credential owner to revoke/rotate if genuine; review removal safely. History rewriting requires separate explicit authorization. Never allowlist a live credential.'
    elif finding.category == 'dependency':
        action = 'Review a patched version, bundled code and build-time exposure; regenerate lockfiles and test compatibility.'
    else:
        action = 'Prepare a root-cause fix with regression tests and related-instance review; retain independent PR review.'
    return RemediationPlan(recommended_action=action,
        verification_steps=['Re-run originating scanner against the repaired commit', 'Run repository-specific regression tests and inspect related instances'],
        related_instances_query='Review related instances of the evidence rule; do not execute scanner-supplied text',
        batch_group_key=f'{finding.repository}:{default_branch}:security-run')


class SecurityPipeline:
    def __init__(self, repository: str, target_path: Path | str):
        self.repository = repository
        self.target_path = Path(target_path).resolve()
        self.dispositions_data = load_dispositions()
        self.repositories_data = load_repositories()
        proc = subprocess.run(['git', '-C', str(self.target_path), 'rev-parse', 'HEAD'], capture_output=True, text=True)
        self.source_commit = proc.stdout.strip() if proc.returncode == 0 else None
        dirty = subprocess.run(['git', '-C', str(self.target_path), 'status', '--porcelain'], capture_output=True, text=True)
        if dirty.returncode or dirty.stdout.strip():
            self.source_commit = None  # reviewed revision does not cover a dirty checkout

    def process_findings(self, findings):
        repo = next((r for r in self.repositories_data['repositories'] if r['repository'] == self.repository), {})
        for finding in findings:
            finding.validation = validate_finding(finding, self.dispositions_data, self.repositories_data, self.source_commit)
            finding.remediation = plan_remediation(finding, finding.validation, repo.get('default_branch', 'main'))
        return findings
