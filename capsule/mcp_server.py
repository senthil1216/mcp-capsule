"""MCP-compatible tool surface (FastMCP).

Exposes read_file, run_command, and github_create_pr_stub over MCP. Every tool is
a thin shim that builds a ToolCall and routes it through Gateway.invoke() — the
gateway remains the single enforcement point. The MCP layer adds NO authority of
its own.

Important (spec): never call input() / read stdin inside the stdio server — a
blocking prompt corrupts the JSON-RPC transport. Approval (Milestone F) uses an
out-of-band channel, never a blocking prompt here.
"""

from __future__ import annotations

import os
from typing import Any

from fastmcp import FastMCP

from capsule.gateway import Gateway
from capsule.models import SourceRef, ToolCall
from capsule.tools_loader import register_default_handlers


def build_server(
    workspace: str | None = None, gateway: Gateway | None = None
) -> tuple[FastMCP, Gateway]:
    """Build a FastMCP server backed by a Capsule gateway.

    Returns (server, gateway) so callers/tests can inspect the same gateway the
    tools dispatch through (shared taint store, audit log, etc.)."""
    gw = gateway or Gateway()
    register_default_handlers(gw)
    ws = workspace or os.getcwd()
    mcp: FastMCP = FastMCP("capsule")
    counter = {"n": 0}

    def _invoke(
        tool: str, arguments: dict[str, Any], source_refs: list[dict] | None = None
    ) -> dict:
        counter["n"] += 1
        call = ToolCall(
            call_id=f"mcp_{counter['n']:03d}",
            tool=tool,
            arguments=arguments,
            workspace=ws,
            source_refs=[SourceRef(**s) for s in (source_refs or [])],
        )
        return gw.invoke(call).model_dump(mode="json")

    @mcp.tool
    def read_file(path: str) -> dict:
        """Read a file from the workspace. Returns the gateway ToolResult
        (decision, content, content_ref, taint, trace, diff)."""
        return _invoke("read_file", {"path": path})

    @mcp.tool
    def run_command(command: str) -> dict:
        """Run a shell command in the workspace sandbox. Returns the gateway
        ToolResult (decision, sandboxed output, trace, diff)."""
        return _invoke("run_command", {"command": command})

    @mcp.tool
    def github_create_pr_stub(title: str, body: str = "") -> dict:
        """Create a pull-request event through a controlled stub. Approval-gated;
        tainted body content triggers approval_required. Returns the gateway
        ToolResult."""
        return _invoke("github_create_pr_stub", {"title": title, "body": body})

    return mcp, gw


def main() -> None:
    mcp, _ = build_server(workspace=os.getcwd())
    mcp.run()  # stdio transport by default


if __name__ == "__main__":
    main()
