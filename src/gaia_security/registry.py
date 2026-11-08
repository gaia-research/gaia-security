"""Load only trusted governance files, never policy from the scan target."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tomllib
from gaia_security.contracts import validate_disposition
from gaia_security.schema import validate_instance
from typing import Any


def find_repo_root(start_dir: Path | None = None) -> Path:
    # start_dir is deliberately ignored: the target cannot supply its own approvals.
    root = Path(os.environ.get('GAIA_SECURITY_ROOT', Path(__file__).resolve().parents[2]))
    if not (root / 'registry/repositories.json').is_file():
        raise ValueError('Governance checkout missing: set GAIA_SECURITY_ROOT to a trusted gaia-security checkout')
    return root.resolve()


def load_repositories(base_dir: Path | None = None) -> dict[str, Any]:
    return json.loads((find_repo_root() / 'registry/repositories.json').read_text())


def load_dispositions(base_dir: Path | None = None) -> dict[str, Any]:
    root = find_repo_root()
    data = json.loads((root / 'registry/dispositions.json').read_text())
    validate_instance(data,json.loads((root/'schemas/dispositions.schema.json').read_text()),root/'schemas')
    for entry in data['dispositions']:
        validate_disposition(entry)
    return data


def _find_profile_file(profiles_dir: Path, filename_patterns: list[str]) -> Path | None:
    return next((profiles_dir / p for p in filename_patterns if (profiles_dir / p).is_file()), None)


def validate_gitleaks_config(path: Path) -> tuple[bool, str]:
    try:
        data = tomllib.loads(path.read_text())
        assert data.get('extend', {}).get('useDefault') is True
        assert not data.get('allowlist'), 'Global allowlists require explicit review; not allowed in baseline'
        return True, 'TOML syntax and baseline invariants; native execution still required'
    except Exception as exc:
        return False, str(exc)


def validate_osv_scanner_config(path: Path) -> tuple[bool, str]:
    try:
        data = tomllib.loads(path.read_text())
        assert not data.get('IgnoredVulns'), 'No baseline advisory suppression'
        return True, 'TOML syntax; native execution still required'
    except Exception as exc:
        return False, str(exc)


def validate_codeql_config(path: Path) -> tuple[bool, str]:
    try:
        data = json.loads(path.read_text())
        assert data['forbid_duplicate_workflow_when_default_active'] is True
        return True, 'Governance JSON; does not change GitHub setup'
    except Exception as exc:
        return False, str(exc)


def validate_yaml_structure(path: Path, required_keys: list[str] | None = None) -> tuple[bool, str]:
    # Baseline YAML profiles use JSON syntax, a strict YAML 1.2 subset, for
    # real parsing without a third-party YAML runtime dependency.
    try:
        data = json.loads(path.read_text())
        assert isinstance(data, dict)
        for key in required_keys or []:
            assert key in data, f'Missing {key}'
        return True, 'Parsed JSON-compatible YAML; scanner semantics need native validator'
    except Exception as exc:
        return False, str(exc)


def validate_all_profiles(base_dir: Path | None = None) -> dict[str, Any]:
    root = Path(base_dir) if base_dir else find_repo_root()
    result: dict[str, Any] = {'profiles': {}, 'registry': {}, 'schemas': {}, 'all_valid': True}
    checks = {
        'gitleaks/gitleaks.toml': validate_gitleaks_config,
        'osv-scanner/osv-scanner.toml': validate_osv_scanner_config,
        'codeql/codeql-profile.json': validate_codeql_config,
        'semgrep/gaia-security.yml': lambda p: validate_yaml_structure(p, ['rules']),
        'trivy/trivy.yaml': lambda p: validate_yaml_structure(p, ['scan']),
        'dependabot/dependabot.minimal.yml': lambda p: validate_yaml_structure(p, ['version', 'updates']),
    }
    for rel, validator in checks.items():
        ok, message = validator(root / 'profiles' / rel)
        result['profiles'][rel] = {'valid': ok, 'message': message}
        result['all_valid'] &= ok
    for directory, names in [('registry', ['repositories.json', 'dispositions.json']), ('schemas', ['finding.schema.json', 'repository-registry.schema.json', 'scan-report.schema.json', 'steward-handoff.schema.json', 'dispositions.schema.json'])]:
        for name in names:
            try:
                data = json.loads((root / directory / name).read_text())
                assert isinstance(data, dict)
                if name == 'repositories.json':
                    repos = data['repositories']
                    assert len({r['repository'] for r in repos}) == len(repos)
                if name == 'dispositions.json':
                    for entry in data['dispositions']:
                        validate_disposition(entry)
                if directory == 'schemas':
                    assert data['type'] in ('object', 'array') and '$schema' in data
                ok, message = True, 'Parsed JSON and required invariants; full schema validation is a development check'
            except Exception as exc:
                ok, message = False, str(exc)
            result[directory][name] = {'valid': ok, 'message': message}
            result['all_valid'] &= ok
    return result
