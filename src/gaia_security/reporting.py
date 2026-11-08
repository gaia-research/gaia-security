"""Restricted audit outputs. No scanner snippets or raw diagnostic output are published."""
from datetime import datetime, timezone
from gaia_security.redaction import redact_structure

COVERAGE_LIMITATIONS = [
    'Scanner detections are candidates, not proof of exploitation or safety.',
    'Business logic, authorization across services, prompt semantics, host permissions and deployment context require independent investigation.',
    'Gitleaks covers the working tree, not full Git history. Trivy adapter covers misconfigurations, not image/OS CVEs.',
    'No path-based or devDependency-based automatic dismissal. Bundled dependencies may execute in production.',
    'Unknown, unavailable, failed, or partially parsed scanners are coverage gaps, never clean results.',
    'Redaction is defense in depth, not permission to publish a report; findings and metadata remain restricted until reviewed.'
]

def to_report_dict(findings, statuses, posture=None, repository=None, raw_detections_count=None, metadata=None):
    return redact_structure({
        'schema_version': '1.0.0', 'repository': repository or (findings[0].repository if findings else 'unknown'),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'handling': 'RESTRICTED: local owner-only evidence; no automatic public upload',
        'scanners_run': [s.scanner for s in statuses if s.executed],
        'scanners_telemetry': [s.to_dict() for s in statuses],
        'complete': bool(statuses) and all(s.complete for s in statuses),
        'posture': posture.to_dict() if posture else None,
        'stage_a_metrics': {'raw_detections': raw_detections_count if raw_detections_count is not None else sum(s.findings_count for s in statuses), 'deduplicated_findings':len(findings)},
        'summary': {'total_findings':len(findings), 'pending_validation':sum(f.validation.disposition=='pending_validation' for f in findings)},
        'coverage_limitations': COVERAGE_LIMITATIONS,
        'metadata': metadata or {}, 'findings': [f.to_dict() for f in findings]})


def render_markdown_report(report):
    # Markdown is still restricted; escape data to prevent rendering injected HTML.
    import html
    safe = lambda v: html.escape(str(v)).replace('|','\\|').replace('\n',' ')
    lines = ['# Gaia Security audit (restricted)', '', '**Not approved for public disclosure.**',
        f"Repository: {safe(report['repository'])}", f"Complete requested coverage: {report['complete']}",
        '', '## Scanner evidence', '|Scanner|Executed locally|Complete|Version|Exit|Findings|', '|---|---|---|---|---|---|']
    for status in report['scanners_telemetry']:
        lines.append('|'+ '|'.join(safe(status.get(k)) for k in ('scanner','executed','complete','version','exit_code','findings_count'))+'|')
    lines.extend(['','## Stage B / C','All detections remain pending unless exact revision-bound review evidence was supplied. Repairs require explicit approval.',
        '|Finding|Category|Severity|Disposition|','|---|---|---|---|'])
    for f in report['findings']:
        lines.append('|'+ '|'.join(safe(x) for x in [f['finding_id'],f['category'],f['raw_severity'],f['validation']['disposition']])+'|')
    lines += ['', '## Coverage limitations', *['- '+x for x in COVERAGE_LIMITATIONS]]
    return '\n'.join(lines)+'\n'
