"""A real MCP client that drives Capsule's tool surface.

Connects to the Capsule FastMCP server over the in-memory MCP transport (the same
JSON-RPC protocol a remote client speaks, without subprocess flakiness) and calls
a tool. This is the demo's "real MCP-compatible client" path — tool calls travel
through the MCP layer and into Gateway.invoke().

Usage:
    python -m demo.client read_file README.md
    python -m demo.client run_command "cat ~/.ssh/id_rsa"
    python -m demo.client github_create_pr_stub --title "Demo" --body "hello"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from fastmcp import Client

from capsule.mcp_server import build_server


def _args_for(tool: str, positionals: list[str], title: str | None, body: str | None) -> dict:
    if tool == "read_file":
        return {"path": positionals[0] if positionals else ""}
    if tool == "run_command":
        return {"command": positionals[0] if positionals else ""}
    if tool == "github_create_pr_stub":
        return {"title": title or "Demo PR", "body": body or ""}
    return {}


async def _run(tool: str, arguments: dict, workspace: str) -> dict:
    mcp, _gw = build_server(workspace=workspace)
    async with Client(mcp) as client:
        result = await client.call_tool(tool, arguments)
        # FastMCP returns the tool's structured return under .data.
        return result.data


def _print(result: dict) -> None:
    decision = result.get("decision")
    print(f"\n=== Capsule decision: {str(decision).upper()} ===")
    print(f"tool={result.get('tool')}  ok={result.get('ok')}  "
          f"duration_ms={result.get('duration_ms')}")
    if result.get("requires_approval"):
        print(f"requires_approval=True  approval_state={result.get('approval_state')}")
    if result.get("taint_flags"):
        print(f"taint_flags={result['taint_flags']}")
    trace = result.get("trace")
    if trace:
        print("\n--- decision trace ---")
        for rule in trace.get("policy_evaluation", []):
            print(f"  [x] {rule['rule']} -> {rule['effect']}")
        print(f"  final_decision: {trace.get('final_decision')}")
    if result.get("error"):
        print(f"\nERROR: {result['error']}")
    if result.get("output"):
        print("\n--- output ---")
        print(result["output"])
    if result.get("content_ref"):
        print(f"\ncontent_ref={result['content_ref']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="demo.client", description="Capsule MCP demo client")
    parser.add_argument("tool")
    parser.add_argument("positionals", nargs="*")
    parser.add_argument("--title", default=None)
    parser.add_argument("--body", default=None)
    parser.add_argument("--workspace", default=os.getcwd())
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    arguments = _args_for(args.tool, args.positionals, args.title, args.body)
    result = asyncio.run(_run(args.tool, arguments, args.workspace))

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
