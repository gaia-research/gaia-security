# Initial security inventory

## Provenance and preflight
Read-only reconnaissance was completed **before foundation implementation** by three `worker-flash-medium` lanes (`antigravity/gemini-3.8-flash`, medium effort, general profile for shell/API access, task restricted to read-only). Argon lead was verified via Pi environment (`antigravity/gemini-4-argon`, high); founder later explicitly transferred lead to Sol (`openai/gpt-6.1-sol`, high). `@parke.dev/pi-subagent` availability and agent files were inspected; dry-run roster preflight preceded dispatch. Max four workers ran in the initial implementation campaign; subsequent review used explicit `worker-astra` / `openai/gpt-6-astra` medium, no fallback.

GitHub account `mbtiongson1` authenticated with repo/workflow/read:org scopes; organization creation allowed and target admin/push permissions confirmed. Secrets/tokens are not reproduced here. Local environment is Android aarch64 Termux, Python 3.14.6, Node 24.17.0, git/gh, native Gitleaks; Linux arm64 OSV/Trivy need the recorded local compatibility wrappers. No remote runner credentials were assumed. Supported hosted workflow target is standard Ubuntu/Python 3.12.

## Snapshot (2026-11-08, paginated GETs rechecked during integration)
|Control|Skill Tree|Skill Heaven|Gaia Security (new bootstrap)|
|---|---|---|---|
|Visibility|Public|Public|Public|
|CodeQL mode|Default setup configured|Default setup configured|Not configured; approval queued|
|Suite / threat model / schedule|default / remote / weekly|default / remote / weekly|No active scan|
|Effective analysis languages|Python, JavaScript/TypeScript, Actions|Python, JavaScript/TypeScript, Actions|Pending|
|Repository CodeQL workflow|None (expected for default setup)|None (expected for default setup)|None|
|CodeQL historical / fixed / open|50 / 49 / 1|43 / 2 / 41|API unavailable/no configured analysis|
|Dependabot alerts|Disabled (API denied)|146 total: 140 fixed, 4 auto-dismissed, 2 open|Not enabled|
|Automatic dependency security updates|Disabled|Enabled|Disabled|
|Secret scanning|Enabled; zero native alerts returned|Enabled; zero native alerts returned|Disabled|
|Push protection|Disabled|Disabled|Disabled|
|Private vulnerability reporting|Enabled|Enabled|Disabled, interim Tree private intake|
|SECURITY.md before mission|Absent|Present with detailed trust boundary policy|Only bootstrap README/LICENSE|
|Semgrep / Trivy / Gitleaks / OSV configuration before mission|None found|None found|New foundation|
|Dependabot YAML / Renovate before mission|None found|None found|Template only, no automatic adoption|

Default setup API lists actions, javascript, javascript-typescript, python, typescript; analyses normalize JS/TS into one category. Skill Tree latest main analyses inspected: commit `3778d37bfcf93f25174c528cde78e20151ac21ef`, CodeQL 2.27.4, three categories, 2026-11-07. Heaven: `c7bcee5045711306f6d602ae92437d54448e15ca`, three categories, 2026-11-08. Analysis ID 2121179597 is an analysis record, not a setup ID. No advanced query packs or custom suites were found.

Counts describe observations, not validated vulnerability totals. Specific alert payloads, locations, exploit details, raw scanner reports and private evidence are intentionally not published.

## Existing native/shared infrastructure
- Skill Tree: 45 direct workflow files at inventory, additional disabled crawler definitions; scope/concurrency guards, branch and metadata/Verifier ownership gates; existing timeout coverage is mixed and not changed. CODEOWNERS names founder and established collaborators. Named-skill static analyzer, HTML sink guard, pickle references guard, historical credential disposition integrity, pip-audit collector and Steward security sensors are retained.
- Skill Heaven: detailed SECURITY.md; deterministic MCP/status/profile/console bundle checks, typecheck/tests, installer and harness compatibility checks, private reporting and native update integrations. SDK URI-template build-time patch retained. No CODEOWNERS found. Main ruleset enforces PRs, linear history and non-fast-forward protections; no changes made.
- Steward: existing policy, locks, evidence/repair interfaces and integration-PR conventions inspected in Skill Tree and research repository. Class A/B/C authority and founder locks stay intact.
- No organization `.github` repository was accessible; `.github-private` contained no shared security workflows. Community-profile API is not authoritative for SECURITY.md presence (Heaven's file exists). Existing research CI churn policy favors local checks, path scoping and no needless full matrix scans.

## API reproduction (GET only)
```bash
gh api repos/gaia-research/gaia-skill-tree/code-scanning/default-setup
gh api 'repos/gaia-research/gaia-skill-tree/code-scanning/analyses?per_page=10'
gh api --paginate --slurp 'repos/gaia-research/gaia-skill-tree/code-scanning/alerts?state=open&per_page=100'
gh api repos/gaia-research/gaia-skill-tree/private-vulnerability-reporting
gh api repos/gaia-research/gaia-skill-tree/vulnerability-alerts
gh api repos/gaia-research/gaia-skill-tree --jq .security_and_analysis
# Repeat for gaia-skill-heaven. Keep full alert output in restricted storage.
```
For count-only postprocessing pipe slurped results to external jq; gh does not support --slurp with its own --jq. A denied API is unknown/unavailable, never an empty clean feed.

## Creation decision
gaia-security returned HTTP 404 after authenticated organization inventory. It was created public via gh, matching public initial targets. Minimal README/LICENSE bootstrap commit established a PR base; all security capability content is proposed on an unmerged feature branch. Repository creation/bootstrap is distinct from settings mutations; none of the latter were performed.
