# Security and coordinated disclosure

Gaia Security is the canonical governance, scanner-profile and vulnerability-management reference for Gaia Research. Individual repositories retain their own execution and GitHub-native controls.

## Report privately
**Do not publish exploitable details, secrets, user data or private evidence in public issues, PRs, gists or logs.**

For Skill Tree or Skill Heaven, use the affected repository's enabled GitHub Private Vulnerability Reporting:
- [Skill Tree private report](https://github.com/gaia-research/gaia-skill-tree/security/advisories/new)
- [Skill Heaven private report](https://github.com/gaia-research/gaia-skill-heaven/security/advisories/new)

**Gaia Security's own private reporting is not yet enabled.** Until founder approval enables it, use the Skill Tree private channel above, prefixing the private report title with “Gaia Security”. The same founder maintains these repositories. This is a temporary private intake route, not an instruction to open a public issue. Never send credentials; use synthetic reproductions and redacted evidence.

We welcome good-faith reports, including unvalidated scanner candidates. Do not test production destructively, access another user's data, persist access, social-engineer people, or scan outside explicitly authorized scope. This policy does not authorize access to third-party systems or promise immunity from third parties. We will not pursue action against good-faith research complying with this policy on systems we control.

Response targets (not guarantees): acknowledge within three business days; triage high-impact reports promptly; agree remediation and coordinated disclosure milestones with the reporter. Security maintainers and founder approve publication. Do not promise a fix or CVE from scanner output alone.

Supported baseline: current default branches and supported releases of each repository; report other versions for assessment.

See [disclosure](governance/VULNERABILITY_DISCLOSURE.md), [triage](governance/TRIAGE_AND_REMEDIATION.md), [ownership](governance/OWNERSHIP_AND_ESCALATION.md) and [approval queue](governance/GITHUB_SETTINGS_APPROVAL_QUEUE.md).
