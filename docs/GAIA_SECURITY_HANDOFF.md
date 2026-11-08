# Gaia Security foundational implementation handoff
Date: 2026-11-08. Proposed for independent review; **not merged or deployed**.

## 1. Architecture and implementation
This is Gaia Research's canonical governance/profile/normalization foundation, not a central scan service or runtime dependency. Federated repositories retain scanning execution and GitHub-native alerts. The zero-third-party-runtime-dependency Python 3.11+ package implements discovery, local/remote posture inventory, authorized native scanner adapters, advisory alias/package deduplication, restricted reports and advisory Steward export.

Detection -> six-point evidence-based validation -> authorized remediation/verification. New detections are **pending** with unknown assessment fields. No path/devDependency heuristics dismiss or prove findings. Trusted dispositions are exact-repository/finding, clean-revision, full-evidence-SHA-256 and expiry bound, with explicit reviewer/evidence requirements and runtime schema/semantic validation. The registry starts empty; no fabricated human approvals or accepted risks are shipped. Reports cannot authorize code changes or supply target-controlled policy. Export checks schema, report/checkout revision, GitHub origin, reconstructed canonical identities and reviewed evidence digests.

Governance policies cover disclosure, prioritization, ownership, onboarding, scanner configuration, triage, remediation verification and Steward boundaries. JSON schemas align wire outputs. One compatible integration PR per repository/run is the default. There is no automatic dispatch, repair, PR merge, release or deployment code.

The optional reusable/manual workflow scans the caller's onboarded public repository, checks a pinned governance SHA and installs SHA-256-verified pinned scanners. It never uploads detailed findings to public artifacts. Local/approved private-runner execution is the durable evidence path. Lean path-scoped CI validates contracts; no new automatic scanner workflow is installed in either initial target.

## 2. Existing security infrastructure discovered
See the self-contained [inventory](INVENTORY.md), produced from pre-implementation reconnaissance and authenticated read-only API checks. Both initial targets use working **CodeQL default setup**, default query suite, remote threat model, weekly schedule, Python / JavaScript-TypeScript / Actions coverage. Recent main analyses were checked independently of workflow files. No advanced workflow is added or replaced.

Skill Tree retains its native security scanner, DOM/model guards, historical credential-disposition guard, pip-audit/Steward sensors, ownership gates and founder locks. Skill Heaven retains its SECURITY.md trust model, deterministic bundles, pinned SDK build patch, harness/installer checks, native update integration and branch rules. Zero declared dependencies does not mean bundled SDK/zod code is absent.

Gaia Security did not exist (authenticated 404). A public repository and minimal README/LICENSE bootstrap commit established the PR base. This is the only direct default-branch content operation; security capability changes remain in the integration PR. New repository CodeQL/PVR/secret-scanning settings were observed disabled and left unchanged. Interim private intake uses Skill Tree's existing enabled channel, documented in SECURITY.md.

## 3. Changes made
- Governance/SECURITY.md/CODEOWNERS, onboarding registry, scanner profiles and JSON schemas.
- Python standard-library CLI and native Gitleaks/OSV/Trivy/Semgrep adapters; CodeQL/Dependabot open-alert API ingestion, pagination and explicit incomplete states.
- Owner-only no-overwrite JSON/Markdown reports; counts-only normal scan receipt; redaction as defense in depth (not permission to publish).
- SHA-256-checked Linux amd64/arm64 scanner installer; explicit pinned manual/reusable workflow and lean contract CI.
- Regression tests for conservative triage, trusted policy loading, alias/package dedup, scanner failure reporting, serialization/schema contracts, redaction and Steward non-authorization.
- Companion integration PRs add/preserve SECURITY.md and small defensive source/test changes without changing target workflows or settings. Each target carries its own handoff.

## 4. Validation evidence
### Automated package checks
At the initial implementation checkpoint, `PYTHONPATH=src python3 -m unittest discover -s tests -q`: **46 tests passed** after the initial shared-review corrections (0.815s on Python 3.14.6). Includes thirteen adversarial boundary tests and an optional native Gitleaks fixture test covering 90 accepted spellings. Includes actual Draft 2020-12 schema/instance checks with development-only jsonschema, workflow YAML parsing, unknown/null validation, missing-policy failure and native-adapter mocks. `validate-configs` and `selftest` pass. A copied source tree built a wheel and installed successfully into an isolated venv; the installed `gaia-sec --help` and `selftest` passed from outside the source directory with explicit `GAIA_SECURITY_ROOT`. The packaging manifest is included, and lean CI now also exercises this installed entry point. [Hosted foundation run 42486147425](https://github.com/gaia-research/gaia-security/actions/runs/42486147425) passed on code commit `f1a70694c15fe4a7a7976f9a7f6615fd2d67cde1`: 46 tests collected, 45 passed and the optional native Gitleaks test skipped; installed CLI selftest passed. Syntax/profile checks are explicitly labeled; they do not claim every native rule's semantics or cloud execution is validated.

### Native execution, not fabricated clean scans
- **Gitleaks:** central extended-default profile executed on all three worktrees. Initial target observations: Tree 150 candidates, Heaven 0; central tests initially produced 5 synthetic-token candidates. Tests were rewritten to construct dummy values at runtime, without scanner suppressions. Re-run central working-tree scan returned **0 candidates**, exit 0. Local distro binary version string is unreported; this limitation is recorded rather than inventing a version.
- **OSV-Scanner 2.7.0 / Scalibr 0.5.3:** target native scans executed. Tree: 110 advisory records; Heaven: 5; these are candidate records, not validated vulnerabilities. Central package has no recognized dependency sources; native exit 128 explicitly reports no sources and is classified not applicable, **not proof of dependency safety**.
- **Trivy 0.76.2:** filesystem **misconfiguration-only** scans executed with central profile on all three repositories; 0 candidates. No claim of image/OS CVE or “zero production vulnerability” coverage. Final strict-envelope testing initially rejected filesystem output because Trivy legitimately omits optional Metadata. Lead corrected that optional-field handling while retaining required header/type/nested-result checks, added the observed native-shape regression, and re-ran Trivy separately on both target checkouts: **complete=true, exit 0, zero misconfiguration candidates** for each.
- **Semgrep CE core 1.184.0:** pinned PyPI arm64 wheel hash verified; core executed through local glibc/proot after resolving Android loader/certificate differences. Native parser accepted all baseline rules. Static-only Python fixture produced two expected positive rule matches, safe shell=False case not flagged, zero core errors. This is native **core fixture validation**, not a full repository CE Python CLI scan; the latter is unavailable on the host.
- **GitHub API:** read-only paginated open CodeQL/Dependabot ingestion executed. Tree returned 1 CodeQL candidate; Dependabot unavailable/disabled so requested aggregate coverage correctly returned incomplete/exit 2. Heaven returned 41 CodeQL and 2 Dependabot observations; native+API baseline normalized 48 records to 40 candidates. Tree normalized 261 records to 224 candidates. Every baseline candidate remained pending; none was auto-dismissed, risk-accepted or used to authorize a repair.

After the shared-review profile fixes, final selected native re-runs completed: central Gitleaks/OSV/Trivy returned **0 findings** (OSV no-sources/not-applicable); Tree Gitleaks+Trivy returned **148 normalized pending candidates**; Heaven Gitleaks+Trivy returned **0 candidates**. These selected re-runs do not replace the broader dependency/API baseline or establish production safety.

Full native reports/alerts remained owner-only outside Git and are not uploaded. Public evidence is counts/configuration and safe synthetic tests only. Later commit/CI evidence must be checked before merge; working-tree baselines do not claim to certify a final release.

### Independent review loop
Founder requested worker-astra at medium, max three rounds. Round 1 ran explicit `openai/gpt-6-astra`, medium, no fallback. It identified unsafe draft assumptions and workflow/contract gaps. Lead replaced them before integration: trusted policy isolation, tri-state pending validation, no automatic suppression, explicit native failures, aligned schemas, conservative export and restricted evidence handling. Round 2 independently ran all then-current 32 tests and reproduced four additional contract-boundary issues. These were corrected and tested: strict native JSON/nested/pagination envelopes, report revision/origin/canonical identity and evidence-digest binding, runtime schema/semantic validation for dispositions, and ecosystem-aware dependency identity with unknown-bridge isolation. Round 3 independently ran 41 tests and verified revision/origin/canonical identity/evidence binding, strict review records and ecosystem isolation. It withheld readiness because unknown GitHub alert state strings were being skipped as closed. Lead then constrained CodeQL/Dependabot states to their supported enums, made unknown states incomplete, and added snapshot plus live-path mock regressions for both tools and known-closed handling. Final suite: **43 passed**. The original three Astra rounds stopped at that point; no claim of Astra final sign-off or production certification is made.

Founder then explicitly changed the final reviewer to `reviewer-shared`. A dry-run confirmed three read-only lanes using `openai-codex/gpt-6.1-terra`, high, no fallback. The target lane marked both integrations READY FOR REVIEW. Core/workflow lanes identified three remaining issues: unknown Trivy statuses could be skipped; scan-time dispositions did not check checkout origin; custom Gitleaks keyword filters omitted regex-accepted spellings. Lead fixed all three: supported status enum enforcement with incomplete-on-unknown, origin verification before applying scan-time dispositions, and removal of both incomplete custom keyword filters. Regressions cover wrong/missing/matching HTTPS/SSH origins, Trivy unknown/known states and **90 native custom-rule spelling/case variants**. Final local suite: **46 passed**. These final corrections were lead-tested, not independently re-reviewed; shared review was read-only, not production certification.

## 5. Scanner coverage and integration compatibility
|Capability|Implemented/observed|Not claimed|
|---|---|---|
|CodeQL|Preserved target default setup; read-only config/analysis/open-alert inspection|Local CodeQL execution, paid AI Scan, new central setup activation|
|Semgrep CE|Versioned profile, adapter, native core rule/fixture validation|Full target CE CLI execution on Android; semantic completeness of all rules|
|Trivy|Native filesystem misconfiguration adapter/profile|Image/OS/container vulnerability coverage|
|Gitleaks|Native working-tree scan, redacted temporary report|Full Git history or credential validity|
|OSV|Native supported-source dependency scan, advisory aliases/package metadata|Reachability/exploitation proof or all ecosystems|
|Dependabot|Read-only native alert ingestion; low-churn opt-in config template|Settings activation or automatic update adoption in targets|
|Steward|Review-only traceable proposals and one-PR/run batch key|Automatic dispatch, acceptance, repair, merge or widened authority|

## 6. Security limitations
Business logic, authorization across services, dynamic agent/host permissions, natural-language prompt injection, deployment exposure, secret validity and build-time trust require separate investigation. Redaction recognizes finite formats; detailed reports remain restricted even after sanitization. Fingerprints are not encryption. Unknown APIs, unavailable binaries and partial parsing are never clean scans.

File-based workflow posture is a hint, not full YAML/job permission verification. Advanced workflow presence is not proof of successful analysis. Dependency version ranges and development labels are not installed-version or nonreachability proofs. No blanket fixture, lockfile or disposition allowlists are shipped. Reviewed exceptions may expire and cannot apply to dirty/new source revisions.

## 7. Costs and execution requirements
No additional subscription, paid AI feature, metered scanning service or cloud infrastructure enabled. Existing Pi agents/compute and public open-source tooling were used; agent inference consumes existing harness resources and is not represented as literally cost-free. Local CPU, disk and upstream database/download traffic remain operational requirements. Standard public GitHub runners are normally free; larger/private runners and storage require explicit budget review.

Python CLI: standard library, >=3.11. Development checks: jsonschema 4.26.0 / PyYAML 6.0.3. Native tools require installation; installer targets Linux x86_64/aarch64 and intentionally rejects Android's platform identifier. Its isolated download/checksum/extraction path was exercised with simulated Linux host classification on Android: pinned Gitleaks 8.30.1, OSV 2.7.0 and Trivy 0.76.2 arm64 assets all passed SHA-256 verification. This does not certify a real supported Linux host. Termux validation used explicitly documented local compatibility wrappers. At the initial implementation checkpoint the hosted workflow had not executed. The authorized PR #1 correction pass subsequently exercised the actual reusable workflow on hosted Ubuntu/Python 3.12 before merge; see section 10. The workflow_dispatch UI entry point was not used.

## 8. Outstanding issues
- Founder decisions on new central private reporting, native CodeQL/secret scanning and target push protection; private interim intake remains usable.
- Private triage of existing target candidates, with no public payloads or blanket risk acceptance.
- **Skill Tree integration is BLOCKED by hosted Python package CI run 42486164856**: 8,382 tests passed, 5 skipped and one loopback-TLS readiness test failed with CoordinationError. Test/transport files are byte-identical to base; local baseline reproduction could not reach the probe because the OpenSSL executable is absent. Root cause remains unverified. CodeQL, graph and PR guards passed; no TLS/review gate was weakened. The target handoff records the exact unresolved gate.
- Local Android full-suite limitations remain documented; the five platform/projection failures reproduce on unchanged main. Supported-platform Skill Heaven CI subsequently passed at `c300e40431235976bd8179d5b3b7775db7a7915b`: **104 test files / 1,840 tests passed, one skipped**, plus build, Windows installers, harness compatibility and native CodeQL.
- Full Semgrep CE CLI scans of other target repositories remain outside this correction pass. Foundation Linux runtime/fixture validation is now recorded in section 10; this is not exhaustive semantic rule coverage or an activation of other repositories' workflows.
- No full-history secret scan or image/OS vulnerability scan claimed. Future private repository adoption requires credential/isolation/cost review.

## 9. GitHub configuration changes awaiting approval
All exact commands, effects, rollback cautions and cost eligibility notes are in [GITHUB_SETTINGS_APPROVAL_QUEUE.md](../governance/GITHUB_SETTINGS_APPROVAL_QUEUE.md). **None executed.** No organization security settings, branch protection, billing, paid features, private-reporting settings or existing production controls were mutated. The initial implementation branches and PRs were pushed. The current correction pass concerns only [Gaia Security #1](https://github.com/gaia-research/gaia-security/pull/1). Per the operator, Skill Heaven #251 is merged and Skill Tree #2422 is deferred until Steward lands. Neither repository was touched in this pass. The foundation's initial hosted contract check passed; target native CodeQL/CI checks started normally. No auto-merge request was set on either target PR. Review/CI is not authorization to merge or deploy; none was requested or exercised.


## 10. PR #1 targeted corrections and supported Linux receipts
The [operator review comment](https://github.com/gaia-research/gaia-security/pull/1#issuecomment-6722441155) requested only Gitleaks credential-environment isolation and end-to-end Linux workflow validation. Sol remains lead (replacing Argon midway); Terra HIGH is the targeted reviewer. No architecture restart, scanner-profile change, setting mutation, merge or other-repository edit was performed.

### Gitleaks isolation
Both Gitleaks version and scan subprocesses now receive the same copied `scanner_environment()` as other native adapters: credential-named keys matching TOKEN, SECRET, API_KEY or PASSWORD are removed case-insensitively; metrics/version-check settings are disabled. Caller environment, PATH, HOME and certificate settings are preserved. This is the existing key-based environment policy, not a process sandbox or a promise to recognize every possible credential variable name.

`tests/test_scanner_environment.py` checks both calls for clean/findings/failure/malformed-report/timeout/version-timeout cases, checks the shared adapter policy, proves the parent environment is unchanged and checks temporary Gitleaks evidence removal. Five new regression tests in total also cover restricted wrapper success/failure/malformed output, refusal to take over existing evidence, and smoke-scratch cleanup on exceptions. Local suite: **51 tests passed**, Python 3.14.6 (1.857s at code checkpoint below).

### Actual hosted execution
- Code checkpoint: `e1b19d4c2c959692d78d339d24c9a112bc59427d`.
- **[Linux scanner smoke run 42489137203](https://github.com/gaia-research/gaia-security/actions/runs/42489137203): SUCCESS.** PR-scoped `scanner-smoke.yml` calls the actual `manual-comprehensive-scan.yml` reusable workflow with the exact governance head SHA and `scanners: all`. This is not a local emulation or a renamed unit-only workflow.
- Hosted image: **ubuntu-24.04**, Python **3.12.16**. Onboarding and pinned-governance validation, both checkouts, installation, native fixtures, full caller scan and evidence cleanup all succeeded.
- Real installer downloaded and SHA-256-verified **Gitleaks 8.30.1**, **OSV-Scanner 2.7.0**, **Trivy 0.76.2** x86_64 assets. Pinned **Semgrep CE 1.184.0** installed and ran as the full CLI.
- **[Foundation run 42489137206](https://github.com/gaia-research/gaia-security/actions/runs/42489137206): SUCCESS.** 51 tests collected, 50 passed, one optional native Gitleaks test skipped in lean CI; config/selftests and installed-package CLI selftest passed. Native scanner tests are performed in the separate smoke job.

### Positive / negative results
Synthetic files are parsed, never executed or installed as application dependencies. Counts from the successful Linux receipt:

|Native adapter|Positive|Negative|Check|
|---|---:|---:|---|
|Gitleaks|1|0|Generated dummy Gaia MCP key vs short placeholder|
|OSV-Scanner|12 advisory candidates|0|Pinned urllib3 1.26.0 vs resolvable six 1.17.0|
|Trivy misconfig|1|0|Dockerfile root user (`DS-0002`) vs non-root user|
|Semgrep CE|2|0|Pickle/shell=True patterns vs JSON/shell=False|

All eight native fixture scans reported complete execution/config validation. Negative results are scope/time-specific, not safety certificates. A future advisory against the negative dependency should fail the test, not be ignored.

### Incomplete coverage and restricted cleanup
- Real Semgrep CLI with malformed configuration in a disposable, explicitly selected governance copy returned native **7**, CLI **2**, **complete=false**. Checked-in baseline profiles remain unchanged. This proves a native failure is not a clean scan.
- The **same `scripts/run-restricted-scan.sh` used by the workflow** was exercised with success (exit 0), missing tool (exit 2), failing executable (native 7 / exit 2), and malformed native output (native 0 / exit 2). Every case verified evidence deletion; missing/failing/malformed cases remained incomplete.
- Detailed JSON/Markdown file modes were checked as **0600**; private scratch directory mode **0700**. Raw Gitleaks temporary directories were absent after calls. All synthetic scratch is nested under the workflow's always-cleaned evidence root, including fallback cleanup on cancellation.
- The wrapper uses an EXIT cleanup trap and handled INT/TERM exits; the workflow retains an `if: always()` cleanup and verifies absence. Smoke exception cleanup has a regression. This is verified ordinary/handled-failure removal, not forensic secure erasure or a guarantee after SIGKILL.
- Full caller scan completed all four native adapters with **0 candidates**; OSV native 128 was explicitly no-sources/not-applicable, not a dependency-safety claim. Evidence cleanup succeeded after that scan.
- Run artifact API returned **total_count=0**. Only static check names, counts, completion/exit metadata and cleanup receipts were published; no reports, scanner stderr, candidate payloads or credentials were uploaded.

### Validation iterations and limits
Earlier smoke attempts failed as real gates and are retained in Actions history: run 42488413858 used a nonexistent negative dependency, which OSV correctly failed to resolve; 42488639240 / 42488788762 used the wrong expected Trivy ID; 42488933190 showed an unfinished Python fragment was not a deterministic native parse-error fixture. Tests were corrected to use a real pinned advisory-negative package, native ID `DS-0002`, and a deterministic disposable invalid configuration. No detector, baseline profile, advisory ignore or completion policy was weakened to turn these attempts green.

The new PR-only smoke is path-scoped and uses the standard public Linux runner. No subscription, larger/private runner, paid scanner service, public findings artifact or API credential was added. Linux x86_64 is validated here; arm64 hosted execution, other repositories, exhaustive rule semantics, live credential validity, full-history secrets and image/OS CVEs remain outside the receipt.

### Targeted independent review
**Terra HIGH targeted re-review: READY FOR REVIEW — clean within the requested scope.** Run `b940beea-8989-4a4f-a690-f326acf207f7` used `reviewer-shared`, explicitly `openai-codex/gpt-6.1-terra`, high, strictly read-only review profile, zero retries and no fallback models. The reviewer independently read the specified isolation implementation/tests, Linux workflow/harness/wrapper and this handoff section; no concrete material blocker was found. The reviewer did not run commands/tests or access GitHub/other repositories: runtime results, artifact count, hashes and commit/profile identity were lead-provided receipts, not independently attested by the reviewer. No code changed after this review; only handoff/PR evidence was finalized. This is targeted correction readiness, not a renewed architecture approval, production certification or permission to merge.
