"""Approval channel + credential broker tests (Milestone F)."""

import tempfile
from pathlib import Path

import pytest

from capsule import approve as approve_cli
from capsule.approvals import ApprovalQueue
from capsule.gateway import Gateway
from capsule.models import Decision, ToolCall
from tools.github_pr_stub import broker_request


@pytest.fixture
def paths():
    with tempfile.TemporaryDirectory() as d:
        yield {
            "audit": Path(d) / "audit.log",
            "approvals": Path(d) / "pending.jsonl",
            "events": Path(d) / "events.jsonl",
        }


def _gateway(paths):
    return Gateway(audit_path=paths["audit"], approval_path=paths["approvals"])


# --- broker --------------------------------------------------------------
def test_broker_grants_scoped_pr_create():
    d = broker_request("github_create_pr_stub", "pull_request:create")
    assert d.granted and d.scope == "pull_request:create"


def test_broker_denies_over_broad_scope():
    d = broker_request("github_create_pr_stub", "repo:admin")
    assert not d.granted and d.scope is None


# --- enqueue + non-blocking ---------------------------------------------
def test_pr_call_enqueues_and_does_not_block(paths):
    gw = _gateway(paths)
    result = gw.invoke(
        ToolCall(
            call_id="c1", tool="github_create_pr_stub", arguments={"title": "Demo", "body": "hello"}
        )
    )
    assert result.decision == Decision.APPROVAL_REQUIRED
    assert result.approval_id  # a pending record was created
    assert ApprovalQueue(paths["approvals"]).list_pending()
    # No event written yet.
    assert not paths["events"].exists()


def test_approve_writes_event(paths):
    gw = _gateway(paths)
    result = gw.invoke(
        ToolCall(
            call_id="c2", tool="github_create_pr_stub", arguments={"title": "Demo", "body": "hello"}
        )
    )
    rc = approve_cli.main(
        [
            "approve",
            result.approval_id,
            "--queue",
            str(paths["approvals"]),
            "--events",
            str(paths["events"]),
        ]
    )
    assert rc == 0
    assert paths["events"].exists()
    assert "pull_request.created" in paths["events"].read_text()
    # No longer pending.
    assert not ApprovalQueue(paths["approvals"]).list_pending()


def test_deny_writes_no_event(paths):
    gw = _gateway(paths)
    result = gw.invoke(
        ToolCall(
            call_id="c3", tool="github_create_pr_stub", arguments={"title": "Demo", "body": "hello"}
        )
    )
    rc = approve_cli.main(
        [
            "deny",
            result.approval_id,
            "--queue",
            str(paths["approvals"]),
            "--events",
            str(paths["events"]),
        ]
    )
    assert rc == 0  # explicit deny is a successful action
    assert not paths["events"].exists()
    # And the record is resolved as denied, not lingering as pending.
    assert not ApprovalQueue(paths["approvals"]).list_pending()


def test_over_broad_scope_denied_even_on_approve(paths):
    gw = _gateway(paths)
    # Caller requests an over-broad scope.
    result = gw.invoke(
        ToolCall(
            call_id="c4",
            tool="github_create_pr_stub",
            arguments={"title": "Demo", "body": "hi", "scope": "repo:admin"},
        )
    )
    rc = approve_cli.main(
        [
            "approve",
            result.approval_id,
            "--queue",
            str(paths["approvals"]),
            "--events",
            str(paths["events"]),
        ]
    )
    assert rc == 1  # broker denied
    assert not paths["events"].exists()


def test_tainted_pr_body_records_taint_in_approval(paths):
    gw = _gateway(paths)
    gw.taint.register("CAPSULE-TAINT-SENTINEL internal notes do not leak ever", path="NOTES.md")
    result = gw.invoke(
        ToolCall(
            call_id="c5",
            tool="github_create_pr_stub",
            arguments={
                "title": "x",
                "body": "CAPSULE-TAINT-SENTINEL internal notes do not leak ever",
            },
        )
    )
    assert result.decision == Decision.APPROVAL_REQUIRED
    rec = ApprovalQueue(paths["approvals"]).get(result.approval_id)
    assert rec.taint_flags  # the pending record carries the taint flags
