"""github_create_pr_stub: a controlled PR-event stub with a credential broker.

Two axes the spec insists are separate from container isolation:
  1. Approval — a human must release the write (handled out-of-band via the
     approval queue + `capsule-approve` CLI; the gateway never blocks).
  2. Scoped authority — a fake credential broker that can DENY. Requesting
     `pull_request:create` is granted (scoped); an over-broad scope like
     `repo:admin` is denied, so even an approved-by-mistake call cannot perform
     more than the PR creation.

The PR "creation" only ever appends to demo/fake_github_events.jsonl. There is no
real GitHub call and no merge/deploy in v0.1.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from capsule.gateway import Gateway, HandlerOutput
from capsule.models import ToolCall

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVENTS_PATH = _REPO_ROOT / "demo" / "fake_github_events.jsonl"

# The only scope this stub is allowed to wield. Anything broader is denied.
ALLOWED_SCOPES = {"pull_request:create"}


@dataclass
class BrokerDecision:
    granted: bool
    scope: str | None
    reason: str


def broker_request(tool: str, scope: str) -> BrokerDecision:
    """Fake credential broker. Grants a scoped PR-create token; denies over-broad
    scopes such as repo:admin."""
    if scope in ALLOWED_SCOPES:
        return BrokerDecision(granted=True, scope=scope, reason="scoped_grant")
    return BrokerDecision(granted=False, scope=None, reason=f"over_broad_scope:{scope}")


def execute_pr(
    *, title: str, body: str, granted_scope: str, events_path: str | Path = DEFAULT_EVENTS_PATH
) -> str:
    """Append a fake PR-created event. Returns an event reference."""
    path = Path(events_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text().splitlines() if path.exists() else []
    event_ref = f"pr_event_{len(existing) + 1:03d}"
    event = {
        "event_ref": event_ref,
        "type": "pull_request.created",
        "title": title,
        "body": body,
        "granted_scope": granted_scope,
    }
    with path.open("a") as fh:
        fh.write(json.dumps(event) + "\n")
    return event_ref


def github_pr_stub_handler(call: ToolCall, gateway: Gateway) -> HandlerOutput:
    """Reached only if policy ever makes this tool executable directly. Normally
    the tool is approval_required and creation happens via the approve CLI, so
    this handler just steers callers to the out-of-band flow."""
    return HandlerOutput(
        ok=True,
        output="github_create_pr_stub is approval-gated; release via `capsule-approve`.",
        approval_state="pending",
    )
