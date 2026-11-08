# Repository onboarding
1. Confirm owner, authorization, visibility, source revision and permitted environment. Register only intentionally onboarded repositories; candidate discovery is not scan authorization.
2. Inventory SECURITY.md, CODEOWNERS, workflows/native guards, lockfiles, reporting routes, Steward and existing alerts privately.
3. Read GitHub default-setup, analyses, alerts, vulnerability-alerts, private-vulnerability-reporting and security_and_analysis APIs. Distinguish denied/unknown from disabled. Preserve default/advanced CodeQL setup and query suites; missing YAML does not mean disabled.
4. PR a registry entry and SECURITY.md governance link. Preserve valid private reporting channels. Follow existing branch/CI rules.
5. Run authorized baseline scanners in a credential-minimal isolated checkout. Record executed/unavailable/incomplete status, versions, revision and coverage gaps. No source execution or package installation is required by the scan adapters.
6. Investigate all six Stage B questions. Do not discard tests, build scripts or vendored source merely because of location. Store sensitive evidence privately. Record approved, expiring, revision-bound dispositions only after review.
7. Prepare fixes, regression tests, re-scans and one integration PR. Settings changes remain in an explicit approval queue. No merge/deploy authorization is implied.

The reusable workflow supports only onboarded public repositories and scans the caller checkout; future private adoption needs separate credential and cost review. The CLI is usable on local/remote-runner checkouts without Actions.
