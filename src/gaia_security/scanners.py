"""Adapters for maintained scanners. No home-grown vulnerability detectors."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import time
from gaia_security.models import EvidenceRecord, NormalizedFinding, ScannerStatus
from gaia_security.redaction import fingerprint_secret, redact_text
from gaia_security.registry import find_repo_root
from gaia_security.contracts import validate_native

SEVERITY_RANKS = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}

def severity(raw):
    return {'error': 'high', 'warning': 'medium', 'note': 'info', 'unknown': 'info', 'moderate': 'medium'}.get(str(raw).lower(), str(raw).lower()) if str(raw).lower() in set(SEVERITY_RANKS) | {'error','warning','note','unknown','moderate'} else 'info'


def safe_path(value, target):
    path = Path(value)
    if path.is_absolute():
        try:
            return str(path.resolve().relative_to(target))
        except ValueError:
            return '[outside-target]'
    return str(path).removeprefix('./')


def parse_osv(data, target):
    validate_native('osv-scanner',data)
    evidence = []
    for result in data.get('results', []):
        file = safe_path(result.get('source', result.get('packageSource', {})).get('path', ''), target)
        for package in result.get('packages', []):
            pkg = package.get('package', {})
            for vuln in package.get('vulnerabilities', []):
                vid = vuln['id']
                evidence.append(EvidenceRecord('osv-scanner', vid,
                    severity(vuln.get('database_specific', {}).get('severity', 'info')), file, 1, 1,
                    message='Dependency advisory candidate; investigate affected version and exposure',
                    advisory_ids=sorted(set([vid] + vuln.get('aliases', []))),
                    source_url=f'https://osv.dev/vulnerability/{vid}',
                    package_name=pkg.get('name'), package_version=pkg.get('version'), ecosystem=pkg.get('ecosystem')))
    return evidence


def parse_github(scanner, alerts):
    validate_native(scanner+'-alerts',alerts)
    evidence = []
    for item in alerts:
        if item.get('state', 'open') != 'open':
            continue
        if scanner == 'dependabot':
            advisory = item.get('security_advisory', {})
            dep = item.get('dependency', {})
            pkg = dep.get('package', {})
            aid = advisory.get('ghsa_id', 'UNKNOWN')
            ids = [x for x in [aid, advisory.get('cve_id')] if x]
            evidence.append(EvidenceRecord(scanner, aid, severity(advisory.get('severity')), dep.get('manifest_path', ''), 1, 1,
                message='GitHub dependency alert candidate', advisory_ids=ids, source_url=item.get('html_url'),
                package_name=pkg.get('name'), ecosystem=pkg.get('ecosystem')))
        else:
            # Preserve non-CodeQL code scanning tools as such; adapter currently ingests CodeQL only.
            if item.get('tool', {}).get('name', 'CodeQL') != 'CodeQL':
                continue
            rule = item.get('rule', {})
            loc = item.get('most_recent_instance', {}).get('location', {})
            evidence.append(EvidenceRecord('codeql', rule.get('id', 'unknown'), severity(rule.get('security_severity_level') or rule.get('severity')),
                loc.get('path', ''), loc.get('start_line', 1), loc.get('end_line', 1),
                message='GitHub code scanning alert candidate; consult restricted native alert for evidence', source_url=item.get('html_url')))
    return evidence


def scanner_environment():
    """Copy the caller environment, excluding credentials from parser subprocesses."""
    env = dict(os.environ)
    for name in list(env):
        if any(k in name.upper() for k in ('TOKEN', 'SECRET', 'API_KEY', 'PASSWORD')):
            env.pop(name)
    env.update({'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
    return env


class ScannerRunner:
    def __init__(self, target_path, repository_name=None):
        self.target_path = Path(target_path).resolve()
        self.repository = repository_name or self.target_path.name
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository):
            raise ValueError('Use an explicit owner/repository identity')
        self.repo_root = find_repo_root()
        self.profiles_dir = self.repo_root / 'profiles'

    def _run(self, scanner, binary, args, parser, config=None, accepted=(0,), cwd=None):
        status = ScannerStatus(scanner=scanner, available=bool(shutil.which(binary)), command=[binary, *args])
        if not status.available:
            status.notes = 'Binary unavailable; NOT executed or native-config-validated'
            return status, []
        # Scanners are parsers of untrusted source, not authorized GitHub API clients.
        env = scanner_environment()
        start = time.monotonic()
        try:
            ver = subprocess.run([binary, '--version' if binary != 'gitleaks' else 'version'], capture_output=True, text=True, timeout=15, env=env)
            status.version = redact_text(ver.stdout.strip()[:300]) or 'unreported'
            result = subprocess.run(status.command, capture_output=True, text=True, timeout=300, cwd=cwd or self.repo_root, env=env)
            status.executed = True
            status.exit_code = result.returncode
            if (scanner == 'osv-scanner' and result.returncode == 128
                    and 'No package sources found' in result.stderr and not result.stdout.strip()):
                status.complete = True
                status.config_validated = bool(config and config.is_file())
                status.notes = 'Not applicable: OSV recognized no package sources; not a dependency safety claim'
                return status, []
            if result.returncode not in accepted:
                status.notes = 'Scanner failed; no clean result inferred. Inspect local restricted stderr separately.'
                return status, []
            data = json.loads(result.stdout)
            validate_native(scanner,data)
            evidence = parser(data)
            if scanner == 'osv-scanner' and bool(evidence) != (result.returncode == 1):
                raise ValueError('Contradictory OSV exit/result')
            if scanner == 'semgrep-ce' and data.get('errors'):
                status.notes = 'Semgrep reported parse/scan errors: partial coverage'
            else:
                status.complete = True
            status.config_validated = bool(config and config.is_file() and status.complete)
            status.findings_count = len(evidence)
            return status, evidence
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            status.notes = 'Execution timed out or result invalid: incomplete coverage; no clean result inferred'
            return status, []
        finally:
            status.duration_ms = int((time.monotonic() - start) * 1000)

    def run_gitleaks(self):
        config = self.profiles_dir / 'gitleaks/gitleaks.toml'
        # Private temp directory; raw secret report removed even after parse errors.
        with tempfile.TemporaryDirectory(prefix='gaia-sec-') as tmp:
            out = Path(tmp) / 'secrets.json'
            def parser(_):
                records = json.loads(out.read_text())
                validate_native('gitleaks',records)
                return [EvidenceRecord('gitleaks', x.get('RuleID', 'secret'), 'high', safe_path(x.get('File',''), self.target_path),
                    x.get('StartLine',1), x.get('EndLine',1), message='Credential candidate ' + fingerprint_secret(x.get('Secret') or x.get('Match','')),
                    snippet_sha256=hashlib.sha256((x.get('Secret') or x.get('Match','')).encode()).hexdigest()) for x in records]
            # Gitleaks writes a report file rather than stdout. Dedicated wrapper below.
            status = ScannerStatus('gitleaks', available=bool(shutil.which('gitleaks')))
            if not status.available:
                status.notes = 'Binary unavailable'
                return status, []
            args = ['dir', str(self.target_path), '--config', str(config), '--report-format','json', '--report-path', str(out), '--no-banner', '--redact=100']
            # --redact also redacts report secrets; fingerprints then identify the redacted
            # record/location, not usable credentials. Never claim secret-value identity.
            def report_parser(data):
                return parser(data)
            # Reuse execution telemetry with report substituted, keeping stderr out of reports.
            start = time.monotonic()
            status.command = ['gitleaks', *args]
            env = scanner_environment()
            try:
                ver = subprocess.run(['gitleaks','version'], capture_output=True,text=True,timeout=10,env=env)
                status.version = ver.stdout.strip()[:200]
                result = subprocess.run(status.command, capture_output=True,text=True,timeout=300, cwd=self.repo_root,env=env)
                status.executed, status.exit_code = True, result.returncode
                if result.returncode not in (0,1) or not out.is_file():
                    status.notes = 'Scanner/report failure; incomplete coverage'
                    return status, []
                evidence = report_parser(None)
                if bool(evidence) != (result.returncode == 1):
                    raise ValueError('Contradictory Gitleaks exit/report')
                status.complete = status.config_validated = True
                status.findings_count = len(evidence)
                return status, evidence
            except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
                status.notes = 'Scanner/report failure; incomplete coverage'
                return status, []
            finally:
                status.duration_ms = int((time.monotonic()-start)*1000)

    def run_osv_scanner(self):
        cfg = self.profiles_dir / 'osv-scanner/osv-scanner.toml'
        return self._run('osv-scanner','osv-scanner',['scan','source','-r',str(self.target_path),'--format','json','--config',str(cfg)],
            lambda data: parse_osv(data,self.target_path),cfg,accepted=(0,1))

    def run_trivy(self):
        cfg = self.profiles_dir / 'trivy/trivy.yaml'
        def parse(data):
            records = []
            for result in data.get('Results', []) or []:
                for m in result.get('Misconfigurations', []) or []:
                    if m.get('Status', 'FAIL') != 'FAIL':
                        continue
                    meta = m.get('CauseMetadata', {})
                    records.append(EvidenceRecord('trivy',m.get('ID','unknown'),severity(m.get('Severity')),safe_path(result.get('Target',''),self.target_path),
                        meta.get('StartLine',1),meta.get('EndLine',1),message='Misconfiguration candidate', source_url=m.get('PrimaryURL')))
            return records
        # Complementary misconfiguration coverage only. OSV handles dependencies;
        # no claim of container/image/OS vulnerability scanning here.
        return self._run('trivy','trivy',['fs','--config',str(cfg),'--scanners','misconfig','--quiet','--format','json',str(self.target_path)],parse,cfg)

    def run_semgrep(self):
        cfg = self.profiles_dir / 'semgrep/gaia-security.yml'
        def parse(data):
            return [EvidenceRecord('semgrep-ce',x['check_id'],severity(x.get('extra',{}).get('severity')),safe_path(x['path'],self.target_path),
                x.get('start',{}).get('line',1), x.get('end',{}).get('line',1),message='Semgrep pattern candidate') for x in data.get('results',[])]
        return self._run('semgrep-ce','semgrep',['scan','--metrics=off','--disable-version-check','--config',str(cfg),'--json',str(self.target_path)],parse,cfg)

    def ingest_github_api_alerts(self, api_alerts_override=None):
        statuses, records = [], []
        for name, endpoint in [('codeql','code-scanning'),('dependabot','dependabot')]:
            status = ScannerStatus(name, available=bool(shutil.which('gh')))
            if api_alerts_override is not None:
                alerts = api_alerts_override.get(name, [])
                status.complete = True
                status.notes = 'Cached/test API snapshot; scanner NOT executed locally'
            elif status.available:
                cmd = ['gh','api','--paginate','--slurp',f'repos/{self.repository}/{endpoint}/alerts?state=open&per_page=100']
                status.command = cmd
                try:
                    res = subprocess.run(cmd,capture_output=True,text=True,timeout=90)
                    status.exit_code = res.returncode
                    if res.returncode:
                        status.notes = 'API denied, disabled, or unavailable; unknown coverage'
                        statuses.append(status)
                        continue
                    pages = json.loads(res.stdout)
                    if type(pages) is not list or any(type(p) is not list for p in pages):
                        raise ValueError('Invalid GitHub pagination envelope')
                    alerts = [a for page in pages for a in page]
                    validate_native(name+'-alerts', alerts)
                    status.complete = True
                    status.notes = 'GitHub alert ingestion only; scanner NOT executed locally'
                except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
                    status.notes = 'API ingestion failed; incomplete coverage'
                    statuses.append(status)
                    continue
            else:
                statuses.append(status)
                continue
            try:
                evidence = parse_github(name,alerts)
            except (ValueError, KeyError, TypeError):
                status.complete = False
                status.notes = 'Invalid GitHub alert records; incomplete coverage'
                statuses.append(status)
                continue
            status.findings_count = len(evidence)
            records.extend(evidence)
            statuses.append(status)
        return statuses, records


def canonical_ecosystem(value):
    clean = (value or '').lower()
    return {'pip':'pypi','python':'pypi','node':'npm','node.js':'npm','golang':'go'}.get(clean,clean)


def _category(e):
    if e.scanner == 'gitleaks': return 'secret'
    if e.scanner in ('dependabot','osv-scanner','pip-audit'): return 'dependency'
    if e.scanner == 'trivy': return 'misconfig'
    if e.file_path.startswith('.github/workflows/'): return 'ci-workflow'
    return 'sast'


def _canonical_advisory_id(e):
    ids = sorted(set(e.advisory_ids + [e.rule_id]))
    return next((x for prefix in ('GHSA-','CVE-','PYSEC-') for x in ids if x.startswith(prefix)),e.rule_id)


def deduplicate_evidences(repository, evidences):
    # Connected components over shared advisory aliases; package and manifest
    # scope prevent one GHSA affecting distinct packages from being collapsed.
    clusters = []
    for e in sorted(evidences, key=lambda x:(x.file_path,x.package_name or '',canonical_ecosystem(x.ecosystem) or '~',x.package_version or '~',x.rule_id,x.scanner)):
        matches = []
        for index, cluster in enumerate(clusters):
            first = cluster[0]
            if first.file_path != e.file_path or _category(first) != _category(e): continue
            if _category(e) == 'dependency':
                ids = {a for x in cluster for a in x.advisory_ids + [x.rule_id]}
                same_pkg = first.package_name == e.package_name
                known_versions = {x.package_version for x in cluster if x.package_version}
                same_version = not e.package_version or not known_versions or known_versions == {e.package_version}
                known_ecosystems = {canonical_ecosystem(x.ecosystem) for x in cluster if x.ecosystem}
                same_ecosystem = not e.ecosystem or not known_ecosystems or known_ecosystems == {canonical_ecosystem(e.ecosystem)}
                match = same_pkg and same_version and same_ecosystem and bool(ids & set(e.advisory_ids+[e.rule_id]))
            else:
                match = first.rule_id == e.rule_id and first.line_start == e.line_start
            if match: matches.append(index)
        if _category(e) == 'dependency' and not e.package_version:
            versions = {x.package_version for i in matches for x in clusters[i] if x.package_version}
            if len(versions) > 1:
                matches = []  # unknown version cannot bridge distinct affected versions
        if _category(e) == 'dependency' and not e.ecosystem:
            ecosystems = {canonical_ecosystem(x.ecosystem) for i in matches for x in clusters[i] if x.ecosystem}
            if len(ecosystems) > 1:
                matches = []
        merged = [e]
        for index in reversed(matches): merged.extend(clusters.pop(index))
        clusters.append(merged)
    findings = []
    for cluster in clusters:
        cluster.sort(key=lambda x:(x.scanner,x.rule_id))
        e = cluster[0]
        category = _category(e)
        advisory = _canonical_advisory_id(EvidenceRecord('', '', '', '', advisory_ids=sorted({i for x in cluster for i in x.advisory_ids+[x.rule_id]})))
        versions = sorted({x.package_version for x in cluster if x.package_version})
        ecosystems = sorted({canonical_ecosystem(x.ecosystem) for x in cluster if x.ecosystem})
        identity = [repository,category,e.file_path,e.package_name or '',ecosystems,versions,advisory if category=='dependency' else e.rule_id, '' if category=='dependency' else str(e.line_start)]
        fid = 'GSEC-' + hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:12]
        sev = max((severity(x.raw_severity) for x in cluster), key=lambda s:SEVERITY_RANKS[s])
        findings.append(NormalizedFinding(fid,repository,category,redact_text(f'{category} candidate: {advisory or e.rule_id}'),sev,e.file_path,e.line_start or 1,cluster))
    return sorted(findings,key=lambda f:f.finding_id)
