"""Capability diff: unsafe authority vs requested authority vs granted authority.

This is the artifact that makes the least-privilege story legible. For a given
tool call it shows (a) what the tool would have if run with no gateway, (b) what
its manifest requests, and (c) what the policy decision actually grants.
"""

from __future__ import annotations

from capsule.models import (
    CapabilityDiff,
    CapabilityManifest,
    Decision,
    PolicyDecision,
    ToolCall,
)

# What each tool would have if it ran directly on the host with no gateway.
_UNSAFE_AUTHORITY: dict[str, dict] = {
    "read_file": {
        "filesystem": "host_user_context",
        "network": "full_outbound",
        "credentials": "inherited_environment",
    },
    "run_command": {
        "filesystem": "host_user_context",
        "network": "full_outbound",
        "credentials": "inherited_environment",
        "process": "host_shell",
    },
    "github_create_pr_stub": {
        "filesystem": "host_user_context",
        "network": "full_outbound",
        "credentials": "inherited_environment",
        "api": "github_full",
    },
}

# What the policy decision grants.
_GRANTED_BY_DECISION: dict[Decision, dict] = {
    Decision.SANDBOX: {
        "filesystem": "/workspace:rw (ephemeral copy)",
        "network": "none",
        "credentials": "none",
        "process": "non_root_container",
    },
    Decision.ALLOW: {
        "filesystem": "workspace",
        "network": "none",
        "credentials": "none",
    },
    Decision.APPROVAL_REQUIRED: {
        "api": "github:pull_request:create (on approval)",
        "network": "github_only",
        "credentials": "scoped_pr_token",
    },
    Decision.DENY: {"filesystem": "none", "network": "none", "credentials": "none"},
    Decision.FLAG: {"filesystem": "workspace", "network": "none", "credentials": "none"},
}


def _requested_authority(manifest: CapabilityManifest, tool: str) -> dict:
    entry = manifest.get(tool)
    if entry is None:
        return {}
    caps = entry.capabilities or {}
    requested: dict = {}
    fs = caps.get("filesystem") or {}
    if fs:
        requested["filesystem"] = "workspace"
    net = (caps.get("network") or {}).get("default")
    if net:
        requested["network"] = net
    if (caps.get("process") or {}).get("shell"):
        requested["process"] = "shell"
    api = caps.get("api")
    if api:
        requested["api"] = api.get("provider", "unknown")
    return requested


def build_diff(
    manifest: CapabilityManifest, call: ToolCall, decision: PolicyDecision
) -> CapabilityDiff:
    return CapabilityDiff(
        tool=call.tool,
        unsafe_authority=_UNSAFE_AUTHORITY.get(call.tool, {"authority": "host_user_context"}),
        requested_authority=_requested_authority(manifest, call.tool),
        granted_authority=_GRANTED_BY_DECISION.get(decision.decision, {}),
    )
