"""run_command execution gate — runtime-free invariants (Milestone D).

These do NOT need a container runtime and run in the default suite. They pin the
two properties that keep the default `make test` hermetic and the decision
authoritative:

  - The `sandbox` decision is enforced for every run_command regardless of whether
    a container ever executes.
  - With CAPSULE_SANDBOX_EXEC unset (the default), the handler does NOT execute a
    container — it reports `sandbox_disabled` — so routing a run_command through
    the gateway in a unit test can never silently spawn a container.
"""

import tempfile
from pathlib import Path

from capsule.gateway import Gateway
from capsule.models import Decision, ToolCall
from capsule.tools_loader import register_default_handlers


def _gateway(tmp: str) -> Gateway:
    gw = Gateway(audit_path=Path(tmp) / "audit.log")
    register_default_handlers(gw)
    return gw


def test_decision_is_sandbox_even_with_exec_disabled(monkeypatch):
    monkeypatch.delenv("CAPSULE_SANDBOX_EXEC", raising=False)
    with tempfile.TemporaryDirectory() as d:
        res = _gateway(d).invoke(
            ToolCall(call_id="c", tool="run_command", arguments={"command": "ls"}, workspace=d)
        )
        assert res.decision == Decision.SANDBOX


def test_exec_disabled_does_not_run_a_container(monkeypatch):
    monkeypatch.delenv("CAPSULE_SANDBOX_EXEC", raising=False)
    with tempfile.TemporaryDirectory() as d:
        res = _gateway(d).invoke(
            ToolCall(call_id="c", tool="run_command", arguments={"command": "echo hi"}, workspace=d)
        )
        # Decision still enforced; execution withheld and reported honestly.
        assert res.decision == Decision.SANDBOX
        assert res.ok is False
        assert "sandbox_disabled" in (res.error or "")


def test_empty_command_is_rejected(monkeypatch):
    monkeypatch.setenv("CAPSULE_SANDBOX_EXEC", "1")  # even with exec on, no command to run
    with tempfile.TemporaryDirectory() as d:
        res = _gateway(d).invoke(
            ToolCall(call_id="c", tool="run_command", arguments={"command": "   "}, workspace=d)
        )
        assert res.ok is False
        assert "no_command" in (res.error or "")
