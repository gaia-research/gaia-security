"""Secret redaction and cryptographic fingerprinting engine for Gaia Security."""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Regex patterns matching high-entropy secrets and credential formats
SECRET_PATTERNS = [
    # Private Keys (RSA, DSA, EC, OPENSSH, etc.)
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.MULTILINE,
    ),
    # GitHub Personal Access Tokens (classic, fine-grained, app tokens)
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    # OpenAI and Anthropic API keys
    re.compile(r"\bsk-(?:proj-|live-|ant-api[0-9]{2}-)?[A-Za-z0-9_-]{20,}\b"),
    # Google API Keys (AIza followed by 30-45 chars)
    re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b"),
    # AWS Access Key IDs
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-(?:[0-9A-Za-z]{10,48}-)+[0-9A-Za-z]{10,48}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b"),
    # JWT tokens (3 parts separated by dots, starting with eyJ)
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]


def fingerprint_secret(raw: str) -> str:
    """Return a 12-hex SHA-256 fingerprint for a secret without exposing the secret bytes."""
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"[REDACTED:sha256={digest}]"


def redact_text(text: str) -> str:
    """Detect and replace all recognized raw secrets with their SHA-256 fingerprints."""
    if not text or not isinstance(text, str):
        return text

    redacted = text
    for pattern in SECRET_PATTERNS:
        def _replace_match(m: re.Match[str]) -> str:
            val = m.group(0)
            return fingerprint_secret(val)

        redacted = pattern.sub(_replace_match, redacted)

    # Neutralize terminal control characters as well as credential formats.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", redacted)


def contains_raw_secret(text: str) -> bool:
    """Return True if text contains any recognized unredacted raw secret."""
    if not text or not isinstance(text, str):
        return False
    return any(pattern.search(text) is not None for pattern in SECRET_PATTERNS)


def redact_structure(obj: Any) -> Any:
    """Recursively redact secrets across dictionaries, lists, tuples, and strings."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {redact_text(k) if isinstance(k, str) else k: redact_structure(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_structure(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_structure(v) for v in obj)
    if isinstance(obj, set):
        return {redact_structure(v) for v in obj}
    return obj
