"""Policy engine.

Evaluates a ToolCall against the capability manifest and policy config, and
produces a PolicyDecision plus a DecisionTrace. Dynamic, per-call conditions
(workspace boundary, taint matches) layer on top of this static posture and are
applied by the gateway/tools; this module owns the static per-tool decision and
the precedence rule for combining effects.
"""

from __future__ import annotations

from typing import Any

from capsule.models import (
    CapabilityManifest,
    Decision,
    DecisionTrace,
    PolicyDecision,
    Risk,
    RuleEval,
    ToolCall,
)

# Strongest-wins precedence. When several rules fire, the final decision is the
# most restrictive effect. This ordering is canonical and is also reused when a
# taint escalation needs to be merged with the base decision.
_PRECEDENCE: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.FLAG: 1,
    Decision.SANDBOX: 2,
    Decision.APPROVAL_REQUIRED: 3,
    Decision.DENY: 4,
}


def stronger(a: Decision, b: Decision) -> Decision:
    """Return the more restrictive of two decisions."""
    return a if _PRECEDENCE[a] >= _PRECEDENCE[b] else b


class PolicyEngine:
    def __init__(self, manifest: CapabilityManifest, policy: dict[str, Any]):
        self.manifest = manifest
        self.policy = policy or {}

    def evaluate(self, call: ToolCall) -> PolicyDecision:
        rules: list[RuleEval] = []
        tool = call.tool

        manifest_entry = self.manifest.get(tool)
        policy_tools: dict[str, Any] = self.policy.get("tools", {})
        unknown_effect = (
            self.policy.get("defaults", {}).get("unknown_tool", "deny")
        )

        # Unknown tool -> deny (default-deny is the whole point of a gateway).
        if manifest_entry is None or tool not in policy_tools:
            rules.append(
                RuleEval(rule="unknown_tool", matched=True, effect=unknown_effect)
            )
            trace = DecisionTrace(
                tool=tool,
                policy_evaluation=rules,
                final_decision=Decision(unknown_effect),
            )
            return PolicyDecision(
                decision=Decision(unknown_effect),
                risk=Risk.HIGH,
                reasons=["tool_not_in_manifest_or_policy"],
                trace=trace,
            )

        tool_policy = policy_tools[tool]
        base = Decision(tool_policy.get("base_decision", "deny"))
        risk = Risk(tool_policy.get("risk", manifest_entry.default_risk.value))
        sandbox_profile = tool_policy.get("sandbox_profile")
        reasons: list[str] = [f"manifest_default_risk={manifest_entry.default_risk.value}"]

        rules.append(
            RuleEval(rule=f"{tool}_base_decision", matched=True, effect=base.value)
        )

        # Surface the capability posture as trace rules so the trace reads like a
        # real evaluation, not a single lookup.
        caps = manifest_entry.capabilities or {}
        net_default = (caps.get("network") or {}).get("default", "none")
        if net_default == "none":
            rules.append(
                RuleEval(rule="network_default_deny", matched=True, effect="network=none")
            )
            reasons.append("network_default_deny")
        if (caps.get("process") or {}).get("shell"):
            rules.append(
                RuleEval(rule="shell_tools_are_high_risk", matched=True, effect=base.value)
            )
            reasons.append("tool_requires_shell")
        if base == Decision.SANDBOX:
            rules.append(
                RuleEval(rule="workspace_only_mount", matched=True, effect="mount=workspace_copy:rw")
            )
            reasons.append("workspace_only_mount")

        trace = DecisionTrace(tool=tool, policy_evaluation=rules, final_decision=base)
        return PolicyDecision(
            decision=base,
            risk=risk,
            reasons=reasons,
            requires_approval=(base == Decision.APPROVAL_REQUIRED),
            sandbox_profile=sandbox_profile,
            trace=trace,
        )

    def escalate(self, decision: PolicyDecision, to: Decision, reason: str) -> PolicyDecision:
        """Merge a dynamic escalation (e.g. a taint match) into a base decision,
        keeping the more restrictive effect and recording it in the trace."""
        new_decision = stronger(decision.decision, to)
        rules = list(decision.trace.policy_evaluation) if decision.trace else []
        rules.append(RuleEval(rule=reason, matched=True, effect=to.value))
        trace = DecisionTrace(
            tool=decision.trace.tool if decision.trace else "",
            policy_evaluation=rules,
            final_decision=new_decision,
        )
        return decision.model_copy(
            update={
                "decision": new_decision,
                "reasons": [*decision.reasons, reason],
                "requires_approval": decision.requires_approval
                or new_decision == Decision.APPROVAL_REQUIRED,
                "trace": trace,
            }
        )
