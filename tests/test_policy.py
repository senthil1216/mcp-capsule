"""Policy engine + gateway flow tests (Milestone A)."""

import tempfile
from pathlib import Path

import pytest

from capsule.gateway import Gateway
from capsule.models import Decision, ToolCall
from capsule.policy import PolicyEngine, stronger
from capsule.registry import load_manifest, load_policy


@pytest.fixture
def engine():
    return PolicyEngine(load_manifest(), load_policy())


def test_unknown_tool_denied(engine):
    decision = engine.evaluate(ToolCall(call_id="c", tool="rm_rf_world"))
    assert decision.decision == Decision.DENY


def test_read_file_allows(engine):
    decision = engine.evaluate(
        ToolCall(call_id="c", tool="read_file", arguments={"path": "README.md"})
    )
    assert decision.decision == Decision.ALLOW


def test_run_command_sandboxed(engine):
    decision = engine.evaluate(
        ToolCall(call_id="c", tool="run_command", arguments={"command": "ls"})
    )
    assert decision.decision == Decision.SANDBOX
    assert decision.sandbox_profile == "docker_no_network_readonly_workspace"


def test_github_stub_requires_approval(engine):
    decision = engine.evaluate(
        ToolCall(call_id="c", tool="github_create_pr_stub", arguments={"title": "x"})
    )
    assert decision.decision == Decision.APPROVAL_REQUIRED
    assert decision.requires_approval is True


def test_precedence():
    assert stronger(Decision.ALLOW, Decision.DENY) == Decision.DENY
    assert stronger(Decision.FLAG, Decision.SANDBOX) == Decision.SANDBOX
    assert stronger(Decision.APPROVAL_REQUIRED, Decision.FLAG) == Decision.APPROVAL_REQUIRED


def test_gateway_flow_emits_trace_and_diff():
    with tempfile.TemporaryDirectory() as d:
        gw = Gateway(audit_path=Path(d) / "audit.log")
        result = gw.invoke(ToolCall(call_id="c1", tool="run_command", arguments={"command": "ls"}))
        assert result.decision == Decision.SANDBOX
        assert result.trace is not None
        assert result.trace.final_decision == Decision.SANDBOX
        assert result.diff is not None
        assert result.diff.unsafe_authority  # populated
        assert result.diff.granted_authority["network"] == "none"
        # Audit line written.
        assert (Path(d) / "audit.log").exists()


def test_gateway_denies_unknown_tool_without_executing():
    with tempfile.TemporaryDirectory() as d:
        gw = Gateway(audit_path=Path(d) / "audit.log")
        result = gw.invoke(ToolCall(call_id="c2", tool="nope"))
        assert result.decision == Decision.DENY
        assert result.ok is False
        assert result.error.startswith("denied_by_policy")
