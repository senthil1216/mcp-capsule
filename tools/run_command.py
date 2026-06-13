"""run_command tool handler (Milestone D).

run_command is a taint *sink* (its arguments are scanned against the taint store
by the gateway) and a sandboxed capability: the policy decision is `sandbox`, and
this handler executes the command inside a hardened, network-isolated container
(see sandbox/runner.py).

Two things are deliberately separated:

  - The *decision* (`sandbox`, network denied) is enforced by the gateway for
    every call, independent of any runtime. That is the security guarantee.
  - *Execution* is gated behind CAPSULE_SANDBOX_EXEC so the default test suite
    stays runtime-free and deterministic — a unit test that routes a run_command
    through the gateway must not silently spawn a container. The bench and demo
    opt in by setting the env var.

When execution is disabled or no container runtime is available, the handler
reports that honestly (ok=False with a `sandbox_disabled` / `sandbox_unavailable`
reason) so the benchmark records "not yet measured" rather than asserting a
containment it never exercised.
"""

from __future__ import annotations

import os

from capsule.gateway import Gateway, HandlerOutput
from capsule.models import ToolCall

_EXEC_ENV = "CAPSULE_SANDBOX_EXEC"
_TRUTHY = {"1", "true", "yes", "on"}


def _exec_enabled() -> bool:
    return os.environ.get(_EXEC_ENV, "").strip().lower() in _TRUTHY


def run_command_handler(call: ToolCall, gateway: Gateway) -> HandlerOutput:
    command = str(call.arguments.get("command", "")).strip()
    if not command:
        return HandlerOutput(ok=False, error="run_command:no_command")

    if not _exec_enabled():
        # The sandbox decision is already enforced by the gateway; only physical
        # execution is gated. Signalled as not-ok so the bench treats it as
        # unmeasured rather than as a clean (empty) run.
        return HandlerOutput(
            ok=False,
            error=f"sandbox_disabled: set {_EXEC_ENV}=1 to execute (decision=sandbox enforced)",
            sandbox_params={"runtime": "disabled", "network": "none"},
        )

    # Lazy import: keeps the docker dependency out of the module import path.
    from sandbox.runner import run_in_sandbox

    result = run_in_sandbox(command, workspace=call.workspace, network="none")
    if not result.ran:
        return HandlerOutput(
            ok=False,
            error=result.error or "sandbox_unavailable",
            sandbox_params=result.params,
        )

    body = result.output
    if result.exit_code is not None:
        tail = f"[exit_code={result.exit_code}]"
        body = f"{body}\n{tail}" if body else tail
    return HandlerOutput(ok=True, output=body, sandbox_params=result.params)
