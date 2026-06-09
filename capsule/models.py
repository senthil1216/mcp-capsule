"""Core data model for Capsule.

These types are what make Capsule feel like a *capability gateway* rather than a
generic command runner. Shapes follow the spec (§3 of the operational plan):
ToolCall, ToolResult, CapabilityManifest, PolicyDecision, DecisionTrace,
CapabilityDiff, TaintLabel, AuditEvent.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Canonical decision values.
#
# These five are the ONLY decision strings used anywhere — the policy engine,
# the PolicyDecision.decision field, the trace, the audit log, and all prose.
# No synonyms ("block", "approve", "isolate", ...). This is a hard rule from the
# spec: a fixed vocabulary is what lets the trace and report be machine-checked.
# ---------------------------------------------------------------------------
class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"
    APPROVAL_REQUIRED = "approval_required"
    FLAG = "flag"


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Inbound
# ---------------------------------------------------------------------------
class SourceRef(BaseModel):
    """An OPTIONAL caller-declared provenance hint.

    Capsule never *depends* on this for enforcement — taint matching is
    content-based (see capsule/taint.py). It is accepted only as a confidence
    signal because a malicious caller will not honestly declare provenance.
    """

    ref: str
    source_type: str = "repo_file"
    path: Optional[str] = None
    taint: str = "untrusted_repo_content"


class ToolCall(BaseModel):
    call_id: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    workspace: Optional[str] = None
    agent_id: str = "demo-agent"
    user_id: str = "demo-user"
    source_refs: list[SourceRef] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Capability manifest (loaded from tool_registry.yaml)
# ---------------------------------------------------------------------------
class ToolCapabilities(BaseModel):
    description: str = ""
    default_risk: Risk = Risk.MEDIUM
    # Free-form capability block; kept as a dict so the manifest stays the source
    # of truth and the policy engine can interpret known keys (filesystem,
    # network, process, api, credentials) without a rigid schema fight.
    capabilities: dict[str, Any] = Field(default_factory=dict)


class CapabilityManifest(BaseModel):
    tools: dict[str, ToolCapabilities] = Field(default_factory=dict)

    def get(self, tool: str) -> Optional[ToolCapabilities]:
        return self.tools.get(tool)


# ---------------------------------------------------------------------------
# Policy output
# ---------------------------------------------------------------------------
class RuleEval(BaseModel):
    rule: str
    matched: bool
    effect: str


class DecisionTrace(BaseModel):
    tool: str
    policy_evaluation: list[RuleEval] = Field(default_factory=list)
    final_decision: Decision


class PolicyDecision(BaseModel):
    decision: Decision
    risk: Risk = Risk.MEDIUM
    reasons: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    sandbox_profile: Optional[str] = None
    trace: Optional[DecisionTrace] = None


# ---------------------------------------------------------------------------
# Capability diff — unsafe vs requested vs granted authority
# ---------------------------------------------------------------------------
class CapabilityDiff(BaseModel):
    tool: str
    unsafe_authority: dict[str, Any] = Field(default_factory=dict)
    requested_authority: dict[str, Any] = Field(default_factory=dict)
    granted_authority: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Taint
# ---------------------------------------------------------------------------
class TaintLabel(BaseModel):
    content_ref: str
    source_type: str = "repo_file"
    path: Optional[str] = None
    taint: str = "untrusted_repo_content"
    trusted: bool = False
    content_sha256: Optional[str] = None
    shingles: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
class AuditEvent(BaseModel):
    timestamp: str
    call_id: str
    tool: str
    decision: Decision
    risk: Risk = Risk.MEDIUM
    reasons: list[str] = Field(default_factory=list)
    sandbox_profile: Optional[str] = None
    sandbox_params: dict[str, Any] = Field(default_factory=dict)
    taint_flags: list[str] = Field(default_factory=list)
    approval_state: Optional[str] = None
    granted_scope: Optional[str] = None
    ok: bool = True
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------
class AttackReplayResult(BaseModel):
    attack: str
    mode: str  # "unsafe" | "safe"
    kind: str
    expected_decision: Optional[str] = None
    actual_decision: Optional[str] = None
    host_secret_visible: bool = False
    network_attempted: bool = False
    network_blocked: Optional[bool] = None
    tainted_outbound: Optional[bool] = None
    tainted_handled: Optional[bool] = None
    passed: bool = False
    duration_ms: int = 0
    note: str = ""


# ---------------------------------------------------------------------------
# Outbound
# ---------------------------------------------------------------------------
class ToolResult(BaseModel):
    call_id: str
    tool: str
    decision: Decision
    ok: bool = True
    output: Optional[str] = None
    error: Optional[str] = None
    content_ref: Optional[str] = None
    taint: Optional[TaintLabel] = None
    taint_flags: list[str] = Field(default_factory=list)
    trace: Optional[DecisionTrace] = None
    diff: Optional[CapabilityDiff] = None
    requires_approval: bool = False
    approval_state: Optional[str] = None
    approval_id: Optional[str] = None
    duration_ms: int = 0
