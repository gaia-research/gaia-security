# Gaia Security

Canonical security governance, scanner profiles and vulnerability-management contracts for Gaia Research. **Govern centrally; execute in each repository.** No central server, runtime coupling or paid service is required.

Start with [SECURITY.md](SECURITY.md) for private disclosure. **Do not post findings or exploit details to public issues.** Gaia Security private reporting is pending founder approval; Skill Tree's enabled private reporting is the interim channel.

## What works
- Versioned [governance](governance/SECURITY_POLICY.md), [onboarding registry](registry/repositories.json) and [profiles](governance/SCANNER_STANDARDS.md).
- Python 3.11+ standard-library CLI: discovery, read-only local/GitHub posture inspection, native scanner execution, advisory normalization/deduplication, restricted JSON/Markdown reports, and advisory Steward proposals.
- Three stages: **A detection -> B evidence-backed validation -> C authorized repair/verification**. New detections remain pending; paths, devDependency labels and scanner consensus do not prove safety/exploitation.
- Lean contract CI plus [manual/reusable workflow](.github/workflows/manual-comprehensive-scan.yml), with pinned scanner downloads and no automatic public evidence upload.

## Quick start (no pip install needed)
Use a trusted checkout. Inspect code and the scan scope before invocation:
```bash
git clone https://github.com/gaia-research/gaia-security.git
cd gaia-security
export GAIA_SECURITY_ROOT="$PWD"
export PYTHONPATH="$PWD/src"
python3 -m gaia_security discover
python3 -m gaia_security validate-configs
python3 -m gaia_security selftest
python3 -m unittest discover -s tests -v
python3 -m gaia_security inspect-posture \
  --repo gaia-research/gaia-skill-tree --path ../gaia-skill-tree --github-api
```

The CLI's standard-library runtime is independent of scanners. Development contract tests additionally use `jsonschema==4.26.0` and `PyYAML==6.0.3`. Installing the Python package requires `GAIA_SECURITY_ROOT` pointing to the reviewed governance checkout; target repositories cannot supply approvals/profiles.

## Install maintained scanners explicitly
Linux x86_64/aarch64:
```bash
python3 scripts/install-scanners.py --destination "$HOME/.local/gaia-security-tools"
export PATH="$HOME/.local/gaia-security-tools:$PATH"
# Semgrep CE needs a supported Python/Linux environment; use an isolated venv:
python3 -m pip install 'semgrep==1.184.0'
```
The installer checks pinned upstream release SHA-256 digests and refuses overwrites. It does not install Semgrep or modify system packages. Native Termux Android is not standard Linux/glibc: OSV/Trivy may need proot and Semgrep may require a Linux environment. Record these limitations rather than substituting homemade detectors.

## Authorized scan
Scans parse source/lockfiles, not run target code or install target dependencies. Do not pass production secrets into scanner environments. Use a restricted, isolated checkout/runner and approved network access:
```bash
mkdir -m 700 /tmp/gaia-private-evidence
python3 -m gaia_security scan \
  --repo gaia-research/gaia-skill-tree --path ../gaia-skill-tree \
  --scanners gitleaks,osv-scanner,trivy,semgrep-ce --include-github-api \
  --output-json /tmp/gaia-private-evidence/report.json \
  --output-md /tmp/gaia-private-evidence/report.md
```
Choose a subset explicitly with `--scanners`. Missing/failing requested scanners return **2** (incomplete); findings alone do not imply exploitation or command failure. Outputs are created mode 0600 with no overwrite/symlink following. Terminal output is counts-only. GitHub API mode uses existing `gh` authentication read-only and paginates open alerts; API ingestion is NOT a local CodeQL/Dependabot scan.

Gitleaks covers working-tree files, Trivy covers misconfigurations, OSV covers supported dependency sources, Semgrep covers the checked-in CE rules. CodeQL default setup remains GitHub-owned. An empty dependency graph may be not applicable; it is not a proven all-clear. No image/OS scanning, active production exploitation or business-logic/authorization proof is claimed.

## Review and Steward
All six Stage B questions require investigation. [Disposition entries](registry/dispositions.json) start empty: no agent can fabricate human approval or historical decisions. Trusted reviewed entries are exact-finding, exact-clean-revision, full-evidence-SHA-256 and expiry bound, with runtime type/enum/semantic checks. Applying a reviewed disposition during scanning also requires a matching GitHub checkout origin; otherwise findings remain pending. Detection never authorizes repair.

```bash
python3 -m gaia_security steward-export \
  --input-report /tmp/gaia-private-evidence/report.json \
  --path ../gaia-skill-tree \
  --output /tmp/gaia-private-evidence/steward-proposals.json
```
Export validates the wire schema, requires report/clean-checkout revision and GitHub origin identity agreement, reconstructs canonical finding IDs and re-evaluates evidence-bound trusted policy. Scan a clean committed checkout before export; dirty or stale reports fail closed. Export does not trust report approval flags, dispatch agents or execute repairs. Reviewed actionable proposals retain Finding -> Evidence -> Validation -> Repair -> Verification. Batch compatible repairs into **one integration PR per affected repository/run**, respecting existing merge rules.

## Repository-local manual/reusable execution
Manual workflow requires a reviewed 40-character governance commit input:
```bash
gh workflow run manual-comprehensive-scan.yml -R gaia-research/gaia-security \
  -f governance_ref=REPLACE_WITH_REVIEWED_40_HEX_COMMIT -f scanners=all
```
Run only **after the workflow is merged with explicit approval**; no Actions scan was dispatched in this mission. Future consumer workflow:
```yaml
jobs:
  security:
    uses: gaia-research/gaia-security/.github/workflows/manual-comprehensive-scan.yml@REVIEWED_40_HEX_COMMIT
    with:
      governance_ref: REVIEWED_40_HEX_COMMIT
      scanners: all
    permissions:
      contents: read
```
The workflow scans the **caller repository**, not an arbitrary central target; it checks onboarding. It never uploads findings to public artifacts. For durable restricted reports, use local/approved private-runner CLI execution. No new scanner workflows were added to Skill Tree or Skill Heaven.

## Evidence and approval gates
- [Pre-implementation inventory](docs/INVENTORY.md)
- [Self-contained implementation handoff](docs/GAIA_SECURITY_HANDOFF.md)
- [GitHub settings approval queue](governance/GITHUB_SETTINGS_APPROVAL_QUEUE.md)
- [Steward contract](governance/STEWARD_INTEGRATION.md)

Initial targets preserve working CodeQL default setup and all native controls. No settings, paid subscriptions, merge or deployment is authorized by this repository.
