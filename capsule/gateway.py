"""The Capsule gateway: the single enforcement point.

Every tool call — whether it arrives over the MCP surface, the CLI, or the bench
runner — flows through Gateway.invoke(). The gateway evaluates policy, builds the
decision trace and capability diff, applies content-based taint escalation,
dispatches to the tool handler only when the decision permits execution, redacts
output, and emits an audit event.

Tool handlers are registered, not hard-wired, so later milestones plug in the
real read_file (B), sandboxed run_command (D), and approval-gated PR stub (F)
without changing this file.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from capsule import approvals as _approvals_mod
from capsule import audit as _audit_mod
from capsule.approvals import ApprovalQueue
from capsule.audit import AuditLog, now_iso
from capsule.diff import build_diff
from capsule.fsboundary import classify_read_path
from capsule.models import (
    AuditEvent,
    Decision,
    PolicyDecision,
    TaintLabel,
    ToolCall,
    ToolResult,
)
from capsule.policy import PolicyEngine
from capsule.redaction import redact
from capsule.registry import load_manifest, load_policy
from capsule.taint import TaintMatch, TaintStore

# Arguments on these tools are scanned against the taint store (outbound/write
# surfaces). read_file is a taint *source*, not a sink.
_OUTBOUND_WRITE_TOOLS = {"run_command", "github_create_pr_stub"}

# Decisions under which the tool actually executes.
_EXECUTING_DECISIONS = {Decision.ALLOW, Decision.FLAG, Decision.SANDBOX}


@dataclass
class HandlerOutput:
    output: str | None = None
    error: str | None = None
    ok: bool = True
    content_ref: str | None = None
    taint: TaintLabel | None = None
    taint_flags: list[str] = field(default_factory=list)
    sandbox_params: dict[str, Any] = field(default_factory=dict)
    approval_state: str | None = None
    granted_scope: str | None = None


Handler = Callable[[ToolCall, "Gateway"], HandlerOutput]


class Gateway:
    def __init__(
        self,
        manifest_path: str | Path | None = None,
        policy_path: str | Path | None = None,
        audit_path: str | Path | None = None,
        taint_store: TaintStore | None = None,
        approval_path: str | Path | None = None,
        echo_audit: bool = False,
    ):
        self.manifest = load_manifest(manifest_path) if manifest_path else load_manifest()
        self.policy = load_policy(policy_path) if policy_path else load_policy()
        self.engine = PolicyEngine(self.manifest, self.policy)
        # Resolve defaults dynamically (module attributes) so tests can redirect
        # them to a temp dir without each test passing explicit paths.
        self.audit = AuditLog(audit_path or _audit_mod.DEFAULT_AUDIT_PATH, echo=echo_audit)
        self.taint = taint_store or TaintStore()
        self.approvals = ApprovalQueue(approval_path or _approvals_mod.DEFAULT_APPROVAL_PATH)
        self.handlers: dict[str, Handler] = {}

    def register_handler(self, tool: str, handler: Handler) -> None:
        self.handlers[tool] = handler

    # ------------------------------------------------------------------
    def invoke(self, call: ToolCall) -> ToolResult:
        start = time.perf_counter()

        # Scan outbound args for tainted content exactly once: scan_outbound
        # mutates the cross-call reassembly buffer, so a second scan would
        # double-record. The same matches drive both the decision and the audit.
        taint_matches = (
            self.taint.scan_outbound(self._string_args(call))
            if call.tool in _OUTBOUND_WRITE_TOOLS
            else []
        )

        decision = self.engine.evaluate(call)
        decision = self._apply_dynamic_policy(call, decision, taint_matches)
        diff = build_diff(self.manifest, call, decision)

        taint_flags = self._format_taint_flags(taint_matches)

        approval_id: str | None = None
        if decision.decision in _EXECUTING_DECISIONS:
            out = self._dispatch(call)
        elif decision.decision == Decision.APPROVAL_REQUIRED:
            # Out-of-band: enqueue a pending record and return immediately. Never
            # block here — this path runs inside the MCP stdio server.
            approval_id = self.approvals.enqueue(
                call_id=call.call_id,
                tool=call.tool,
                title=str(call.arguments.get("title", "")),
                body=str(call.arguments.get("body", "")),
                requested_scope=str(call.arguments.get("scope", "pull_request:create")),
                taint_flags=taint_flags,
            )
            out = HandlerOutput(
                ok=True,
                output=f"approval_required: enqueued as {approval_id}; "
                f"release with `capsule-approve approve {approval_id}`",
                approval_state="pending",
            )
        else:  # deny
            reason = decision.reasons[-1] if decision.reasons else "policy"
            out = HandlerOutput(ok=False, error=f"denied_by_policy: {reason}")

        duration_ms = int((time.perf_counter() - start) * 1000)
        output = redact(out.output) if out.output else out.output
        merged_flags = sorted(set(taint_flags) | set(out.taint_flags))

        self.audit.emit(
            AuditEvent(
                timestamp=now_iso(),
                call_id=call.call_id,
                tool=call.tool,
                decision=decision.decision,
                risk=decision.risk,
                reasons=decision.reasons,
                sandbox_profile=decision.sandbox_profile,
                sandbox_params=out.sandbox_params,
                taint_flags=merged_flags,
                approval_state=out.approval_state,
                granted_scope=out.granted_scope,
                ok=out.ok,
                error=out.error,
            )
        )

        return ToolResult(
            call_id=call.call_id,
            tool=call.tool,
            decision=decision.decision,
            ok=out.ok,
            output=output,
            error=out.error,
            content_ref=out.content_ref,
            taint=out.taint,
            taint_flags=merged_flags,
            trace=decision.trace,
            diff=diff,
            requires_approval=decision.requires_approval,
            approval_state=out.approval_state,
            approval_id=approval_id,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    def _dispatch(self, call: ToolCall) -> HandlerOutput:
        handler = self.handlers.get(call.tool)
        if handler is None:
            return HandlerOutput(
                ok=True,
                output=f"[stub] {call.tool} permitted but no handler registered",
            )
        return handler(call, self)

    @staticmethod
    def _format_taint_flags(matches: list[TaintMatch]) -> list[str]:
        """Audit flags from precomputed matches.

        Format is `{taint}:{content_ref}:{kind}`; the transform is appended only
        when it is not the verbatim ("raw") match, so existing flags are
        unchanged and a re-encoded hit reads e.g. `...:substring:base64`.
        """
        flags: list[str] = []
        for m in matches:
            flag = f"{m.taint}:{m.content_ref}:{m.kind}"
            if m.transform != "raw":
                flag += f":{m.transform}"
            flags.append(flag)
        return sorted(set(flags))

    def _apply_dynamic_policy(
        self, call: ToolCall, decision: PolicyDecision, taint_matches: list[TaintMatch]
    ) -> PolicyDecision:
        """Per-call conditions that can change the static decision:
        the read_file workspace boundary and content-based taint escalation."""
        if call.tool == "read_file":
            decision = self._apply_read_file_boundary(call, decision)
        decision = self._apply_taint(call, decision, taint_matches)
        return decision

    def _apply_read_file_boundary(self, call: ToolCall, decision: PolicyDecision) -> PolicyDecision:
        requested = call.arguments.get("path")
        if not requested:
            return self.engine.escalate(decision, Decision.DENY, "read_file:no_path")
        workspace = call.workspace or os.getcwd()
        verdict = classify_read_path(workspace, str(requested))
        if not verdict.allowed:
            return self.engine.escalate(decision, Decision.DENY, f"read_file:{verdict.reason}")
        return decision

    def _apply_taint(
        self, call: ToolCall, decision: PolicyDecision, taint_matches: list[TaintMatch]
    ) -> PolicyDecision:
        """Content-based taint escalation.

        If any outbound/write argument contains content registered in the taint
        store — verbatim, re-encoded, or reassembled across calls (Milestone E) —
        escalate per policy: PR body -> approval_required, network-enabled
        command -> deny, local command -> flag.
        """
        if call.tool not in _OUTBOUND_WRITE_TOOLS or not taint_matches:
            return decision

        if call.tool == "github_create_pr_stub":
            return self.engine.escalate(
                decision, Decision.APPROVAL_REQUIRED, "tainted_content_in_pr_body"
            )
        if call.tool == "run_command":
            cmd = str(call.arguments.get("command", ""))
            if self._command_uses_network(cmd):
                return self.engine.escalate(
                    decision, Decision.DENY, "tainted_content_in_network_command"
                )
            return self.engine.escalate(decision, Decision.FLAG, "tainted_content_in_local_command")
        return decision

    @staticmethod
    def _string_args(call: ToolCall) -> list[str]:
        out: list[str] = []
        for v in call.arguments.values():
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, (list, tuple)):
                out.extend(str(x) for x in v)
        return out

    @staticmethod
    def _command_uses_network(cmd: str) -> bool:
        net_tokens = (
            "curl",
            "wget",
            "nc ",
            "netcat",
            "ssh ",
            "scp ",
            "ftp",
            "http://",
            "https://",
            "telnet",
        )
        low = cmd.lower()
        return any(tok in low for tok in net_tokens)
