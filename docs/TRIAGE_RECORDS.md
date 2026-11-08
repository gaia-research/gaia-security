# Recording an evidence-backed review

The initial disposition registry is deliberately empty. Scanner candidates do not create authority. Do not mark an issue false positive, accept risk or queue a repair solely from a path, dependency label or this CLI's output.

## 1. Obtain a stable baseline
Use an authorized isolated checkout of the affected repository, with the correct GitHub `origin` and a clean committed revision. Run the selected scanners and store the report in an owner-only private directory. Keep the exact scanner versions and source revision. Do not add reports or private evidence to this public repository.

## 2. Investigate all six questions
Determine genuineness, reachable code paths (including bundled/build-time use), security boundary, plausible exploitation, protections and duplicate identity. Use source/call-path evidence and synthetic isolated tests. Record uncertainties; do not turn them into false or true automatically. No active production testing is permitted by these instructions.

## 3. Prepare a review entry, not an auto-approval
For a single finding, calculate the full normalized evidence digest locally:
```python
import json
from gaia_security.models import EvidenceRecord
from gaia_security.contracts import evidence_digest
report = json.load(open('/PRIVATE/PATH/report.json'))
finding = report['findings'][0]  # select the intended finding explicitly
records = [EvidenceRecord.from_dict(e) for e in finding['evidences']]
print(evidence_digest(records))
```
The entry in `registry/dispositions.json` must satisfy `schemas/dispositions.schema.json` and the runtime semantic validator:
- exact `repository`, canonical `finding_id`, reviewed clean `source_commit`;
- full 64-hex `evidence_sha256`, nonempty restricted `evidence_refs`;
- attributable `reviewer`, stable `disposition_id`, timezone-aware `expires_at`;
- `validation` containing all four Boolean investigation answers, `existing_mitigations` list, `duplicate_of` (null or another finding ID), supported disposition/priority/confidence and evidence-backed rationale.

Do not invent reviewer identity, approvals or dates. A proposed exception requires the existing human review gate. Use only sanitized references suitable for public governance; if an entry itself would reveal sensitive information, keep it in an explicitly approved private governance checkout rather than publishing it. A private checkout changes no authority without approval.

Supported reviewed dispositions: `action_required`, `remediated_in_pr`, `false_positive`, `accepted_risk`, `test_fixture_excluded`, `deferred_steward_wave`. `pending_validation` is the default for unreviewed detections, not an approval entry. The runtime refuses invalid combinations, expired records, mismatched evidence and new/dirty revisions. Changing scanner versions or evidence may require a new review even if the location is the same.

## 4. Export advisory repair proposals
Run `steward-export` with the report and clean affected checkout. It checks wire shape, origin, revision, canonical identity and reviewed evidence, and then emits only reviewed `action_required` proposals. Supplied report approval/remediation flags cannot authorize anything.

Proposals still require explicit human/lead repair authorization and existing Steward authority checks. Preserve Finding -> Evidence -> Validation -> Repair -> Verification, add regressions, re-run scanners, search related instances and batch compatible fixes into one integration PR per repository/run. Never merge or deploy without separate authorization. GitHub-native alert state remains repository-owned; this CLI does not dismiss or close alerts.
