"""Out-of-band approval queue.

The MCP stdio transport must never block on input() — a blocking prompt corrupts
the JSON-RPC stream. So when the gateway decides `approval_required`, it does NOT
wait: it appends a pending record here and returns immediately. A separate
`capsule-approve` CLI (capsule/approve.py) later releases or denies the record,
running the credential broker and only then executing the write.

Storage is a simple JSONL file rewritten on resolve — enough for a single-user
v0.1, cleared by deleting the file.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_APPROVAL_PATH = _REPO_ROOT / "demo" / "pending_approvals.jsonl"


@dataclass
class ApprovalRecord:
    id: str
    call_id: str
    tool: str
    title: str
    body: str
    requested_scope: str
    taint_flags: list[str] = field(default_factory=list)
    state: str = "pending"  # pending | approved | denied
    granted_scope: Optional[str] = None
    event_ref: Optional[str] = None
    reason: Optional[str] = None


class ApprovalQueue:
    def __init__(self, path: str | Path = DEFAULT_APPROVAL_PATH):
        self.path = Path(path)
        self._counter = 0

    def _load(self) -> list[ApprovalRecord]:
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text().splitlines():
            if line.strip():
                records.append(ApprovalRecord(**json.loads(line)))
        return records

    def _save(self, records: list[ApprovalRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(json.dumps(asdict(r)) for r in records) + ("\n" if records else ""))

    def enqueue(self, *, call_id: str, tool: str, title: str, body: str,
                requested_scope: str, taint_flags: list[str]) -> str:
        records = self._load()
        new_id = f"appr_{len(records) + 1:03d}_{call_id}"
        records.append(ApprovalRecord(
            id=new_id, call_id=call_id, tool=tool, title=title, body=body,
            requested_scope=requested_scope, taint_flags=taint_flags,
        ))
        self._save(records)
        return new_id

    def list_pending(self) -> list[ApprovalRecord]:
        return [r for r in self._load() if r.state == "pending"]

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        for r in self._load():
            if r.id == approval_id:
                return r
        return None

    def resolve(self, approval_id: str, *, state: str, granted_scope: Optional[str],
                event_ref: Optional[str], reason: Optional[str]) -> Optional[ApprovalRecord]:
        records = self._load()
        out = None
        for r in records:
            if r.id == approval_id:
                r.state = state
                r.granted_scope = granted_scope
                r.event_ref = event_ref
                r.reason = reason
                out = r
        self._save(records)
        return out
