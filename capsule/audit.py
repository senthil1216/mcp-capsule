"""Structured audit log.

Every gateway decision emits one AuditEvent as a JSON line. The log is the
forensic record: tool, decision, sandbox parameters, taint flags, approval
state, granted scope.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from capsule.models import AuditEvent

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_PATH = _REPO_ROOT / "audit.log"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    def __init__(self, path: str | Path = DEFAULT_AUDIT_PATH, echo: bool = False):
        self.path = Path(path)
        self.echo = echo

    def emit(self, event: AuditEvent) -> None:
        line = event.model_dump_json()
        with self.path.open("a") as fh:
            fh.write(line + "\n")
        if self.echo:
            print(f"[audit] {line}")

    def tail(self, n: int = 10) -> list[str]:
        if not self.path.exists():
            return []
        return self.path.read_text().splitlines()[-n:]


def redact_optional(value: Optional[str]) -> Optional[str]:
    return value
