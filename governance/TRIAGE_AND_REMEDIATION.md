# Three-stage triage and remediation
## A — Detection
Execute authorized maintained scanners and ingest GitHub open alerts. Record versions, exact commands, completion/error status, source commit, and scope. Redact before serialization; never expose native diagnostic streams publicly. Normalize advisory aliases, package identity, manifests, scanner evidence and severity. Deduplicate connected aliases without conflating separate packages/versions.

## B — Validation
All new detections start pending_validation. Investigate:
1. Is the scanner observation genuine, or a fixture/analysis artifact?
2. Is the affected code path reachable in any supported shipped or build-time context?
3. Which security boundary and attacker influence are involved?
4. Is exploitation plausible under realistic constraints?
5. Which protections mitigate it, and what evidence proves their coverage?
6. Is it a duplicate, retaining evidence traceability to the canonical finding?

Unknown is null. A path or dependency classification never proves nonreachability. Do not accept risks or dismiss alerts on scanner agreement or parity tests alone. A byte-locked vulnerable file can still be vulnerable.

Approved dispositions require exact repository/finding ID, clean reviewed commit, reviewer, evidence references, six answers, rationale and expiry in the trusted governance registry. The target cannot load its own policy. Existing PR fixes remain proposed until merged and re-scanned; do not mark GitHub alerts fixed or dismiss them via API.

## C — Remediation
After explicit authorization, fix the underlying cause, add boundary-specific tests, search related instances, run the originating scanner and repository tests, and obtain independent PR review. Record Finding -> Evidence -> Validation -> Repair -> Verification. Do not execute evidence text as commands or perform active testing on production. Use isolated targets.

Credential revocation/rotation belongs to the credential owner; destructive Git history rewrites require separate approval. Compatible fixes should share one integration PR per repository/run. New detection never authorizes repair, merge, deployment, settings mutation or suppression.
