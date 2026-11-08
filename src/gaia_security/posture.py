"""Read-only posture inventory. File presence is not proof a control executes."""
from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess
from gaia_security.models import PostureAssessment


def _run_gh_api(endpoint, timeout=20):
    try:
        res = subprocess.run(['gh','api',endpoint],capture_output=True,text=True,timeout=timeout)
        if res.returncode: return res.returncode,None
        return 0,json.loads(res.stdout) if res.stdout.strip() else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return -1,None


def inspect_repository_posture(repo_path, repo_name=None, include_github_api=False, api_override_data=None):
    path = Path(repo_path).resolve()
    name = repo_name or path.name
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',name):
        raise ValueError('Explicit owner/repository required')
    sec = next((p for p in (path/'SECURITY.md',path/'.github/SECURITY.md',path/'docs/SECURITY.md') if p.is_file()),None)
    linked = bool(sec and 'gaia-research/gaia-security' in sec.read_text(errors='replace'))
    workflows = list((path/'.github/workflows').glob('*.yml'))+list((path/'.github/workflows').glob('*.yaml'))
    contents = [p.read_text(errors='replace') for p in workflows]
    advanced = any('github/codeql-action/' in txt for txt in contents)
    default = None
    pvr = secret = push = dep = None
    gaps = []
    if api_override_data is not None:
        default = api_override_data.get('codeql_default_setup_configured')
        pvr = api_override_data.get('private_vulnerability_reporting')
    elif include_github_api:
        code,data = _run_gh_api(f'repos/{name}/code-scanning/default-setup')
        if code==0 and isinstance(data,dict): default = data.get('state')=='configured'
        else: gaps.append('CodeQL default setup API unavailable: unknown, not disabled')
        code,data = _run_gh_api(f'repos/{name}/private-vulnerability-reporting')
        if code==0 and isinstance(data,dict): pvr=data.get('enabled')
        code,data = _run_gh_api(f'repos/{name}')
        if code==0 and isinstance(data,dict):
            security = data.get('security_and_analysis',{})
            secret = security.get('secret_scanning',{}).get('status')=='enabled' if 'secret_scanning' in security else None
            push = security.get('secret_scanning_push_protection',{}).get('status')=='enabled' if 'secret_scanning_push_protection' in security else None
        # Vulnerability alerts differ from automated security-update PRs.
        code,_ = _run_gh_api(f'repos/{name}/vulnerability-alerts')
        dep = True if code==0 else None
    else:
        gaps.append('GitHub API not queried: CodeQL default setup and repository security settings unknown')
    effective = True if default is True else (False if default is False and not advanced else None)
    if advanced:
        gaps.append('Advanced CodeQL workflow present: inspect analyses/runs separately; file presence does not prove active coverage')
    if default is False and not advanced: gaps.append('No configured default CodeQL setup and no advanced workflow observed')
    if not sec: gaps.append('SECURITY.md missing')
    elif not linked: gaps.append('SECURITY.md lacks Gaia Security reference')
    if pvr is False: gaps.append('Private Vulnerability Reporting disabled: approval required to enable')
    if secret is False: gaps.append('GitHub secret scanning disabled')
    if push is False: gaps.append('Secret scanning push protection disabled')
    # Text hints only: do not claim comprehensive YAML/job permission validation.
    perms = all('permissions:' in txt for txt in contents)
    timeouts = all('timeout-minutes:' in txt for txt in contents)
    if not perms: gaps.append('Workflow text audit: missing permissions block(s); manual per-job review required')
    if not timeouts: gaps.append('Workflow text audit: missing timeout declaration(s); manual per-job review required')
    locks = [n for n in ('uv.lock','package-lock.json','pnpm-lock.yaml','poetry.lock','Cargo.lock','go.sum','requirements.txt') if (path/n).is_file()]
    return PostureAssessment(name,bool(sec),linked,advanced,default,effective,pvr,secret,push,dep,locks,perms,timeouts,gaps,'UNASSESSED')
