# Steward integration contract
Gaia Security owns standards, normalization, validation requirements, classification and remediation evidence. Steward retains its own task/repair ledger and existing authority gates; it consumes advisory proposals, not a competing security truth database.

Flow: Finding -> restricted Evidence -> reviewed Validation -> authorized Repair -> independent Verification. Export includes stable finding IDs, evidence references, complete validation, repair spec, verification contract and an explicit requires_human_or_lead_approval status. Reports cannot self-authorize: steward-export re-evaluates findings against current trusted governance and the local reviewed revision.

Only reviewed action_required findings are proposed. Pending, false-positive, accepted-risk, fixture-excluded and already-remediated entries are not repair tasks. No automatic dispatch, repair, PR creation, acceptance or merge is implemented here. Untrusted scanner metadata is never executable.

Batch key: repository:target-branch:security-run. One integration PR per repository per run, batching compatible findings; split only for explicit incompatibility/authorization boundaries. Skill Tree retains merge-commit-only integration topology; Skill Heaven retains linear/squash rules. Do not unfreeze Steward locks or use security packets to expand Class A/B permissions.

Public governance stores standards and sanitized approved references only. GitHub native alerts remain repository-owned; restricted scan evidence is not committed to this public repository. Future adapters must preserve this authority boundary.
