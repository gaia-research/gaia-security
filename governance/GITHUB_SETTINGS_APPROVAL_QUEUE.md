# Founder approval queue — NOT executed

Repository creation and PR content are authorized; settings mutations below are **not**. Request explicit founder approval for each operation before execution. No organization, billing, branch protection or paid settings have been changed. These commands are proposals for eligible public repositories; recheck GitHub eligibility and organization policy first.

## Gaia Security private reporting
Effect: enable the native private intake so the temporary Skill Tree route can be replaced.
```bash
gh api --method PUT repos/gaia-research/gaia-security/private-vulnerability-reporting
# Verification (GET):
gh api repos/gaia-research/gaia-security/private-vulnerability-reporting
# Rollback ONLY if separately approved: gh api --method DELETE repos/gaia-research/gaia-security/private-vulnerability-reporting
```
Free public-repository capability. Disabling an established channel could disrupt reporters; rollback is not automatically authorized.

## Gaia Security secret scanning and push protection
Effect: enable native scanning and block recognized secrets on push (subject to GitHub permissions/policies).
```bash
printf '%s\n' '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' | gh api --method PATCH repos/gaia-research/gaia-security --input -
```
Verification: `gh api repos/gaia-research/gaia-security --jq .security_and_analysis`.
Rollback payload sets those statuses to `disabled`, only with separate approval. No non-provider/AI/paid option is requested.

## Gaia Security CodeQL default setup
Effect: GitHub-managed Python/Actions analysis, including GitHub-managed triggers/schedule. Does NOT add an advanced workflow.
```bash
printf '%s\n' '{"state":"configured","languages":["python","actions"],"query_suite":"default"}' | gh api --method PATCH repos/gaia-research/gaia-security/code-scanning/default-setup --input -
# Verify:
gh api repos/gaia-research/gaia-security/code-scanning/default-setup
```
Free CodeQL for eligible public source; GitHub-hosted compute/network/storage and future private adoption still need budget review. Rollback payload `{"state":"not-configured"}` would disable this control and requires separate approval. Do NOT apply setup mutations to Skill Tree or Skill Heaven: both already work.

## Existing target push protection
Effect: block recognized secret pushes while preserving existing native scanning.
```bash
printf '%s\n' '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}' | gh api --method PATCH repos/gaia-research/gaia-skill-tree --input -
printf '%s\n' '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}' | gh api --method PATCH repos/gaia-research/gaia-skill-heaven --input -
```
Verify each repository's `security_and_analysis`. Free for eligible public repos. Reversal sets only push protection to disabled; requires separate approval.

## Skill Tree Dependabot vulnerability alerts (evaluate first)
Existing `pip-audit`, Steward and optional OSV execution are preserved. Native alerts are disabled; enabling them is independent of automated update PRs:
```bash
gh api --method PUT repos/gaia-research/gaia-skill-tree/vulnerability-alerts
# Verify: gh api repos/gaia-research/gaia-skill-tree/vulnerability-alerts  # 204 on enabled
```
Free native alert feed. Does NOT enable automated security-update PRs or install dependabot.yml. Those are distinct decisions. Rollback DELETE on the same endpoint disables alerts and needs separate approval. No proposal here alters branch rules or existing alert dispositions.
