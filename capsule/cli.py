"""CLI harness for driving the gateway directly.

This exists as a test/demo harness — NOT as the only path to the tools (the MCP
surface in Milestone B is the real client path). It lets you flow a ToolCall
through Gateway.invoke() and see the decision, trace, capability diff, and result.

Examples:
    python -m capsule.cli read_file README.md
    python -m capsule.cli run_command "cat ~/.ssh/id_rsa"
    python -m capsule.cli github_create_pr_stub --title "Demo" --body "hello"
"""

from __future__ import annotations

import argparse
import json
import sys

from capsule.gateway import Gateway
from capsule.models import ToolResult
from capsule.tools_loader import register_default_handlers


def _build_call_arguments(
    tool: str, positionals: list[str], title: str | None, body: str | None
) -> dict:
    if tool == "read_file":
        return {"path": positionals[0]} if positionals else {}
    if tool == "run_command":
        return {"command": positionals[0]} if positionals else {}
    if tool == "github_create_pr_stub":
        return {"title": title or "Demo PR", "body": body or ""}
    # Generic: pack positionals under "args".
    return {"args": positionals}


def _print_result(result: ToolResult) -> None:
    print(f"\n=== Capsule decision: {result.decision.value.upper()} ===")
    print(
        f"tool={result.tool}  call_id={result.call_id}  ok={result.ok}  "
        f"duration_ms={result.duration_ms}"
    )
    if result.requires_approval:
        print(f"requires_approval=True  approval_state={result.approval_state}")
    if result.taint_flags:
        print(f"taint_flags={result.taint_flags}")
    print("\n--- decision trace ---")
    if result.trace:
        for rule in result.trace.policy_evaluation:
            print(f"  [{'x' if rule.matched else ' '}] {rule.rule} -> {rule.effect}")
        print(f"  final_decision: {result.trace.final_decision.value}")
    print("\n--- capability diff ---")
    if result.diff:
        print(json.dumps(result.diff.model_dump(), indent=2))
    print("\n--- output ---")
    if result.error:
        print(f"ERROR: {result.error}")
    if result.output:
        print(result.output)
    if result.content_ref:
        taint_val = result.taint.taint if result.taint else None
        print(f"\ncontent_ref={result.content_ref}  taint={taint_val}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capsule", description="Capsule gateway CLI harness")
    parser.add_argument("tool", help="tool name (read_file, run_command, github_create_pr_stub)")
    parser.add_argument("positionals", nargs="*", help="positional tool arguments")
    parser.add_argument("--title", default=None)
    parser.add_argument("--body", default=None)
    parser.add_argument("--workspace", default=None, help="workspace root for the call")
    parser.add_argument("--call-id", default="cli_001")
    parser.add_argument("--json", action="store_true", help="emit the full ToolResult as JSON")
    args = parser.parse_args(argv)

    gateway = Gateway(echo_audit=False)
    register_default_handlers(gateway)

    from capsule.models import ToolCall

    call = ToolCall(
        call_id=args.call_id,
        tool=args.tool,
        arguments=_build_call_arguments(args.tool, args.positionals, args.title, args.body),
        workspace=args.workspace,
    )
    result = gateway.invoke(call)

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_result(result)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
