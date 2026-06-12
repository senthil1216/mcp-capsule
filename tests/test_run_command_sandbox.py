"""run_command sandbox integration tests (Milestone D).

These exercise the REAL container runtime, so the whole module is marked `docker`
and skipped when no daemon is reachable. They are deselected from the default
`make test` run (addopts: `-m "not docker"`) so the base suite stays runtime-free;
run them explicitly with `pytest -m docker`.

What they pin down — the security invariants behind the bench numbers:
  - egress is blocked under `--network none`, AND the sink is reachable when
    networking is allowed (so "blocked" is a real network block, not an artifact);
  - the root filesystem is read-only, /tmp is writable;
  - the command runs as a non-root user;
  - the host home / secrets are never mounted;
  - the workspace is an ephemeral copy — writes never touch the host workspace.
"""

import tempfile
from pathlib import Path

import pytest

from capsule.gateway import Gateway
from capsule.models import Decision, ToolCall
from capsule.tools_loader import register_default_handlers
from sandbox.runner import _docker_client, run_in_sandbox

# Probe the daemon once; skip the whole module if it (or the SDK) is unavailable.
_client, _reason = _docker_client()
pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(_client is None, reason=_reason or "docker runtime unavailable"),
]


def test_benign_command_runs_in_sandbox():
    r = run_in_sandbox("echo capsule-sandbox-ok", network="none")
    assert r.ran
    assert r.exit_code == 0
    assert "capsule-sandbox-ok" in r.output


def test_runs_as_non_root():
    r = run_in_sandbox("id -u", network="none")
    assert r.ran
    assert r.output.strip() == "1000"


def test_root_filesystem_is_read_only():
    r = run_in_sandbox("touch /should_fail 2>&1 || true", network="none")
    assert r.ran
    assert "Read-only file system" in r.output


def test_tmp_is_writable():
    r = run_in_sandbox("touch /tmp/ok && echo wrote", network="none")
    assert r.ran
    assert r.exit_code == 0
    assert "wrote" in r.output


def test_host_secret_is_not_mounted():
    # The container's HOME is /home/capsule with no .ssh — the host's secret
    # paths are never carried into the sandbox.
    r = run_in_sandbox("cat $HOME/.ssh/id_rsa 2>&1 || true", network="none")
    assert r.ran
    assert "No such file" in r.output


def test_workspace_is_an_ephemeral_copy():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        (ws / "hello.txt").write_text("hi-from-host")
        r = run_in_sandbox(
            "cat /workspace/hello.txt && echo NEW > /workspace/created.txt",
            workspace=str(ws),
            network="none",
        )
        assert r.ran
        assert "hi-from-host" in r.output  # the copy is mounted and readable
        # ...but the write landed in the throwaway copy, never the host workspace.
        assert not (ws / "created.txt").exists()


def test_network_egress_blocked_with_reachable_control():
    """The headline containment invariant, with attribution.

    Posts to a recording sink from a networked container (must arrive) and from a
    `--network none` container (must not). The networked control proves the sink
    is reachable, so the blocked result is attributable to --network none rather
    than to an unreachable address.
    """
    from bench.sink import RecordingSink

    sink = RecordingSink(host="0.0.0.0").start()
    try:
        url = f"http://127.0.0.1:{sink.port}/probe"  # runner rewrites for networked
        run_in_sandbox(
            f"curl -s -m 5 -X POST {url} --data-binary REACH_NET", network="bridge", timeout=25
        )
        run_in_sandbox(
            f"curl -s -m 5 -X POST {url} --data-binary REACH_NONE", network="none", timeout=25
        )
        assert sink.hits_containing("REACH_NET"), "sink must be reachable when networked"
        assert not sink.hits_containing("REACH_NONE"), "--network none must block egress"
    finally:
        sink.stop()


def test_run_command_executes_through_gateway(monkeypatch):
    monkeypatch.setenv("CAPSULE_SANDBOX_EXEC", "1")
    with tempfile.TemporaryDirectory() as d:
        gw = Gateway(audit_path=Path(d) / "audit.log")
        register_default_handlers(gw)
        res = gw.invoke(
            ToolCall(
                call_id="c1",
                tool="run_command",
                arguments={"command": "echo via-gateway"},
                workspace=d,
            )
        )
        assert res.decision == Decision.SANDBOX
        assert res.ok
        assert "via-gateway" in (res.output or "")
