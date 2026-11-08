# Severity and prioritization
Keep scanner severity separate from validated impact and remediation priority. Unknown severity is informational/unknown, not automatically medium. Corroborating scanners may repeat one database and do not independently prove exploitation.

Base severity: critical (catastrophic compromise), high (major boundary failure), medium (material constrained impact), low (limited impact), informational (observation). Record CWE/CVSS when available; do not invent scores.

Stage B answers all six questions: genuine? reachable? boundary crossed? exploitation plausible? protections/mitigations? duplicate? Unknown answers remain null, not false or true. Path names, “devDependency”, offline operation and zero declared runtime dependencies are clues only: bundled code and build tooling can be exposed.

After investigation assign P0 emergency/under 24h, P1/under 7d, P2/under 30d, P3/under 90d, or P4/planned hardening. These are response goals, not unattended action authority. Before validation use UNASSESSED. Accepted risk/false positive requires a named reviewer, rationale, exact finding and revision, evidence references and expiry. Preserve original severity. An exception must not suppress new advisories or future source revisions.
