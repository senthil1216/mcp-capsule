"""Model + decision-vocabulary tests (Milestone A)."""

from capsule.models import (
    AuditEvent,
    CapabilityDiff,
    Decision,
    DecisionTrace,
    PolicyDecision,
    Risk,
    RuleEval,
    ToolCall,
    ToolResult,
)


def test_decision_vocabulary_is_exactly_five():
    assert {d.value for d in Decision} == {
        "allow",
        "deny",
        "sandbox",
        "approval_required",
        "flag",
    }


def test_toolcall_defaults():
    call = ToolCall(call_id="c1", tool="read_file", arguments={"path": "README.md"})
    assert call.agent_id == "demo-agent"
    assert call.source_refs == []


def test_toolresult_roundtrip():
    trace = DecisionTrace(
        tool="run_command",
        policy_evaluation=[RuleEval(rule="r", matched=True, effect="sandbox")],
        final_decision=Decision.SANDBOX,
    )
    result = ToolResult(
        call_id="c1", tool="run_command", decision=Decision.SANDBOX, trace=trace
    )
    data = result.model_dump_json()
    back = ToolResult.model_validate_json(data)
    assert back.decision == Decision.SANDBOX
    assert back.trace.final_decision == Decision.SANDBOX


def test_audit_event_minimal():
    ev = AuditEvent(
        timestamp="2026-06-08T00:00:00+00:00",
        call_id="c1",
        tool="read_file",
        decision=Decision.ALLOW,
        risk=Risk.MEDIUM,
    )
    assert ev.decision == Decision.ALLOW
