"""Advisory handoff only; no dispatch, API mutation, PR creation or repair execution."""
from gaia_security.models import StewardHandoffPacket
from gaia_security.redaction import redact_structure


def build_steward_packets_from_findings(findings):
    packets = []
    for f in findings:
        v = f.validation
        if v.disposition != 'action_required' or not v.disposition_id or v.is_genuine is not True:
            continue
        packets.append(StewardHandoffPacket(f.finding_id,
            [f'{e.scanner}:{e.rule_id}@{e.file_path}:{e.line_start}' for e in f.evidences],
            v.to_dict(), {'recommended_action':f.remediation.recommended_action},
            {'regression_test_requirement':f.remediation.regression_test_requirement, 'verification_steps':f.remediation.verification_steps},
            'requires_human_or_lead_approval', f.remediation.batch_group_key))
    return packets


def generate_steward_dispatch_payloads(findings, repository, target_branch='main', **kwargs):
    # Retained interface name for compatibility. These are proposals, NEVER
    # executable or authorized Steward actions. Do not trust report approval flags.
    items = [p.to_dict() for p in build_steward_packets_from_findings(findings)]
    if not items:
        return []
    return [redact_structure({'schema_version':'1.0.0','target_repository':repository,
        'target_branch':target_branch, 'batch_group_key':f'{repository}:{target_branch}:security-run',
        'authorization_status':'requires_human_or_lead_approval','integration_pr_limit':1,
        'items':items})]
