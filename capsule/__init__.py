"""Capsule — a capability gateway for MCP tools."""

from capsule.gateway import Gateway, HandlerOutput
from capsule.models import (
    CapabilityDiff,
    Decision,
    DecisionTrace,
    PolicyDecision,
    TaintLabel,
    ToolCall,
    ToolResult,
)
from capsule.taint import TaintStore

__version__ = "0.1.0"

__all__ = [
    "Gateway",
    "HandlerOutput",
    "TaintStore",
    "ToolCall",
    "ToolResult",
    "Decision",
    "DecisionTrace",
    "PolicyDecision",
    "CapabilityDiff",
    "TaintLabel",
]
