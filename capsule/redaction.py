"""Secret redaction for tool output and audit records.

v0.1 keeps the high-value patterns (PEM private keys, common token prefixes,
AWS keys, password=/token= assignments). Broad redaction is a "cut first" item;
PEM and token basics are not cuttable.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "PEM_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("ASSIGNED_SECRET", re.compile(r"(?i)\b(password|token|secret|api_key)\s*=\s*\S+")),
]

REDACTED = "[REDACTED:{label}]"


def redact(text: str) -> str:
    if not text:
        return text
    for label, pattern in _PATTERNS:
        text = pattern.sub(REDACTED.format(label=label), text)
    return text
