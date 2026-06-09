"""MCP surface tests (Milestone B).

Uses the in-memory FastMCP transport — the same MCP/JSON-RPC protocol a remote
client speaks — to prove tool calls travel through the MCP layer and into
Gateway.invoke(). Skipped if fastmcp is not installed (base CI job).
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("fastmcp")

from fastmcp import Client  # noqa: E402

from capsule.gateway import Gateway  # noqa: E402
from capsule.mcp_server import build_server  # noqa: E402


def _call(workspace: Path, tool: str, arguments: dict, gateway: Gateway):
    async def go():
        mcp, _ = build_server(workspace=str(workspace), gateway=gateway)
        async with Client(mcp) as client:
            res = await client.call_tool(tool, arguments)
            return res.data

    return asyncio.run(go())


def test_mcp_lists_three_tools():
    async def go():
        mcp, _ = build_server(workspace=".")
        async with Client(mcp) as client:
            tools = await client.list_tools()
            return {t.name for t in tools}

    names = asyncio.run(go())
    assert {"read_file", "run_command", "github_create_pr_stub"} <= names


def test_mcp_read_file_flows_through_gateway():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        (ws / "README.md").write_text("hello from the workspace readme")
        gw = Gateway(audit_path=ws / "audit.log")
        result = _call(ws, "read_file", {"path": "README.md"}, gw)
        assert result["decision"] == "allow"
        assert result["ok"] is True
        assert "hello from the workspace" in result["output"]
        assert result["content_ref"]
        # Proof it went through the gateway: audit log has an entry.
        assert (ws / "audit.log").exists()


def test_mcp_read_file_host_secret_denied():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        gw = Gateway(audit_path=ws / "audit.log")
        result = _call(ws, "read_file", {"path": "~/.ssh/id_rsa"}, gw)
        assert result["decision"] == "deny"
        assert result["ok"] is False


def test_mcp_run_command_is_sandbox_decision():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        gw = Gateway(audit_path=ws / "audit.log")
        result = _call(ws, "run_command", {"command": "ls"}, gw)
        # No runtime needed: the *decision* is sandbox regardless of execution.
        assert result["decision"] == "sandbox"
