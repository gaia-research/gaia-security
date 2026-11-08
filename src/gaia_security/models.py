"""Versioned, tri-state finding contracts. Unknown is not false or proven safe."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict, fields
from typing import Any

class Record:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})

@dataclass
class ScannerStatus(Record):
    scanner: str
    available: bool = False
    executed: bool = False
    config_validated: bool = False
    version: str | None = None
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int = 0
    findings_count: int = 0
    notes: str = ''
    complete: bool = False

@dataclass
class EvidenceRecord(Record):
    scanner: str
    rule_id: str
    raw_severity: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    message: str = ''
    snippet_sha256: str | None = None
    advisory_ids: list[str] = field(default_factory=list)
    source_url: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None

@dataclass
class ValidationAssessment(Record):
    is_genuine: bool | None = None
    is_reachable: bool | None = None
    boundary_crossed: bool | None = None
    exploitation_plausible: bool | None = None
    existing_mitigations: list[str] = field(default_factory=list)
    duplicate_of: str | None = None
    disposition: str = 'pending_validation'
    validated_priority: str = 'UNASSESSED'
    confidence: str = 'low'
    rationale: str = 'Scanner detection only; six-point investigation required'
    disposition_id: str | None = None

@dataclass
class RemediationPlan(Record):
    recommended_action: str = 'Investigate in an isolated authorized checkout before proposing a fix'
    authorization_status: str = 'requires_human_or_lead_approval'
    regression_test_requirement: str = 'Add boundary-specific regression tests after validation'
    verification_steps: list[str] = field(default_factory=list)
    related_instances_query: str = ''
    batch_group_key: str = ''

@dataclass
class NormalizedFinding(Record):
    finding_id: str
    repository: str
    category: str
    title: str
    raw_severity: str
    primary_file: str
    primary_line: int
    evidences: list[EvidenceRecord] = field(default_factory=list)
    validation: ValidationAssessment = field(default_factory=ValidationAssessment)
    remediation: RemediationPlan = field(default_factory=RemediationPlan)

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        data['evidences'] = [EvidenceRecord.from_dict(e) for e in data.get('evidences', [])]
        data['validation'] = ValidationAssessment.from_dict(data.get('validation', {}))
        data['remediation'] = RemediationPlan.from_dict(data.get('remediation', {}))
        return super().from_dict(data)

@dataclass
class StewardHandoffPacket(Record):
    finding_id: str
    evidence_refs: list[str]
    validation_summary: dict[str, Any]
    repair_spec: dict[str, Any]
    verification_contract: dict[str, Any]
    authorization_status: str
    batch_group_key: str

@dataclass
class PostureAssessment(Record):
    repository: str
    security_md_present: bool
    security_md_has_policy_link: bool
    codeql_workflow_present: bool
    codeql_default_setup_configured: bool | None
    codeql_effective: bool | None
    private_vulnerability_reporting: bool | None
    secret_scanning_enabled: bool | None
    secret_scanning_push_protection: bool | None
    dependabot_alerts_enabled: bool | None
    lockfiles_found: list[str] = field(default_factory=list)
    workflow_permissions_restricted: bool = True
    workflow_timeouts_configured: bool = True
    coverage_gaps: list[str] = field(default_factory=list)
    overall_posture_grade: str = 'UNASSESSED'
