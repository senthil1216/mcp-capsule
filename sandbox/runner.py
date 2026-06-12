"""Docker sandbox runner for run_command (Milestone D).

Executes a shell command inside a hardened, network-isolated container against an
*ephemeral copy* of the workspace — matching the authority the policy decision
grants (capsule/diff.py: `/workspace:rw (ephemeral copy)`, `network: none`,
`non_root_container`).

The hardening applied at launch:
  - `network_mode="none"`   — no egress; this is what contains exfil.
  - `read_only=True`        — read-only root filesystem (+ tmpfs /tmp).
  - ephemeral workspace copy — mounted rw at /workspace; the real workspace and
                               the host home/secrets are never mounted.
  - `cap_drop=["ALL"]` + `no-new-privileges` + non-root user.
  - memory / cpu / pids limits and a wall-clock timeout.

The docker SDK is imported lazily inside `run_in_sandbox`, so importing this
module (and therefore `tools.run_command`) never requires docker to be installed.
When the SDK or daemon is unavailable the runner returns `ran=False` with a
`sandbox_unavailable:` reason instead of raising — the bench/report stay honest
("not yet measured") rather than asserting containment that was never exercised.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

IMAGE_TAG = "capsule-sandbox:latest"
_DOCKERFILE_DIR = Path(__file__).resolve().parent

# Ephemeral workspace copies live under the repo, not $TMPDIR. On macOS the
# default temp dir (/var/folders/...) is not in Docker Desktop's file-sharing
# set, so a bind mount of it silently comes up empty; the repo lives under /Users
# which is shared by default. On Linux any local path works, so this is safe
# there too. Each run gets its own throwaway subdir, removed on completion.
_EPHEMERAL_ROOT = _DOCKERFILE_DIR.parent / ".sandbox-runs"
# Don't copy the repo's own bulk/VCS dirs into the sandbox (faster, and avoids
# recursing into the ephemeral-copy root if the workspace happens to be the repo).
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".sandbox-runs", ".venv", "__pycache__", ".pytest_cache"
)

# Resource ceilings for a sandboxed command.
MEM_LIMIT = "256m"
NANO_CPUS = 1_000_000_000  # 1.0 CPU
PIDS_LIMIT = 256
DEFAULT_TIMEOUT_S = 20

# Output cap so a runaway command can't blow up the audit log / transport.
MAX_OUTPUT_BYTES = 64 * 1024

# When a command targets the host loopback (e.g. the bench recording sink), the
# container's own 127.0.0.1 is not the host. For a *networked* run we rewrite it
# to host.docker.internal so egress is genuinely attempted against a reachable
# host — which is what makes "blocked under --network none" a real measurement
# rather than an artifact of an unreachable address. Never applied to a
# `network="none"` run (there is no network to reach anyway).
_LOOPBACK_TOKENS = ("127.0.0.1", "localhost")
_HOST_ALIAS = "host.docker.internal"


@dataclass
class SandboxResult:
    """Outcome of a sandbox execution attempt.

    `ran` is True iff a container actually executed the command (regardless of
    the command's own exit code). `ran=False` means the sandbox could not run at
    all (no SDK / no daemon / image build failure) — the caller should treat
    containment as unmeasured, not as success.
    """

    ran: bool
    exit_code: int | None = None
    output: str = ""
    error: str | None = None
    params: dict = field(default_factory=dict)


def _rewrite_loopback(command: str) -> str:
    out = command
    for tok in _LOOPBACK_TOKENS:
        out = out.replace(tok, _HOST_ALIAS)
    return out


def _docker_client():
    """Return (client, None) on success or (None, reason) if unavailable.

    Imported lazily: a machine without the docker SDK or a running daemon must
    still be able to import this module and run the rest of the gateway.
    """
    try:
        import docker  # noqa: PLC0415  (intentionally lazy)
    except ImportError as e:
        return None, f"sandbox_unavailable: docker SDK not installed ({e})"
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:  # noqa: BLE001 — any connection/daemon error is "unavailable"
        return None, f"sandbox_unavailable: docker daemon unreachable ({e})"
    return client, None


def ensure_image(client) -> None:
    """Build the sandbox image on first use; idempotent and layer-cached."""
    import docker.errors  # noqa: PLC0415

    try:
        client.images.get(IMAGE_TAG)
    except docker.errors.ImageNotFound:
        client.images.build(path=str(_DOCKERFILE_DIR), tag=IMAGE_TAG, rm=True)


def image_available(client) -> bool:
    import docker.errors  # noqa: PLC0415

    try:
        client.images.get(IMAGE_TAG)
        return True
    except docker.errors.ImageNotFound:
        return False


def run_in_sandbox(
    command: str,
    workspace: str | Path | None = None,
    *,
    network: str = "none",
    timeout: int = DEFAULT_TIMEOUT_S,
    env: dict | None = None,
    build_if_missing: bool = True,
) -> SandboxResult:
    """Run `command` in a hardened container. See module docstring for the model.

    `network="none"` (default) isolates the network. `network="bridge"` is used
    only by the egress-containment control to prove the sink is reachable when
    networking is allowed; it also rewrites host loopback to host.docker.internal
    and wires the host-gateway alias.
    """
    networked = network != "none"
    params = {
        "runtime": "docker",
        "image": IMAGE_TAG,
        "network": network,
        "read_only": True,
        "user": "1000:1000",
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "mem_limit": MEM_LIMIT,
        "pids_limit": PIDS_LIMIT,
        "timeout_s": timeout,
    }

    client, reason = _docker_client()
    if client is None:
        return SandboxResult(ran=False, error=reason, params={**params, "runtime": "unavailable"})

    try:
        if build_if_missing:
            ensure_image(client)
        elif not image_available(client):
            return SandboxResult(
                ran=False,
                error=(
                    f"sandbox_unavailable: image {IMAGE_TAG} not built (run `make sandbox-image`)"
                ),
                params={**params, "runtime": "unavailable"},
            )
    except Exception as e:  # noqa: BLE001
        return SandboxResult(
            ran=False,
            error=f"sandbox_unavailable: image build failed ({e})",
            params={**params, "runtime": "unavailable"},
        )

    cmd = _rewrite_loopback(command) if networked else command

    # Ephemeral copy of the workspace: the container gets a throwaway /workspace,
    # never the real one and never the host home.
    tmp_ws: str | None = None
    volumes: dict = {}
    if workspace is not None:
        _EPHEMERAL_ROOT.mkdir(exist_ok=True)
        tmp_ws = tempfile.mkdtemp(prefix="ws-", dir=str(_EPHEMERAL_ROOT))
        dest = Path(tmp_ws) / "workspace"
        shutil.copytree(workspace, dest, symlinks=True, dirs_exist_ok=True, ignore=_COPY_IGNORE)
        volumes[str(dest)] = {"bind": "/workspace", "mode": "rw"}
        params["workspace"] = "/workspace (ephemeral copy)"

    run_kwargs = dict(
        image=IMAGE_TAG,
        command=["sh", "-c", cmd],
        network_mode=network,
        read_only=True,
        user="1000:1000",
        working_dir="/workspace",
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
        mem_limit=MEM_LIMIT,
        nano_cpus=NANO_CPUS,
        pids_limit=PIDS_LIMIT,
        tmpfs={"/tmp": "rw,size=16m"},
        environment={"HOME": "/home/capsule", **(env or {})},
        volumes=volumes,
        detach=True,
    )
    if networked:
        run_kwargs["extra_hosts"] = {_HOST_ALIAS: "host-gateway"}

    container = None
    try:
        container = client.containers.run(**run_kwargs)
        try:
            status = container.wait(timeout=timeout)
            exit_code = int(status.get("StatusCode", -1))
            timed_out = False
        except Exception:  # noqa: BLE001 — SDK raises on read timeout
            try:
                container.kill()
            except Exception:  # noqa: BLE001
                pass
            exit_code = None
            timed_out = True

        logs = b""
        try:
            logs = container.logs(stdout=True, stderr=True)
        except Exception:  # noqa: BLE001
            pass
        output = logs[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        params["exit_code"] = exit_code
        if timed_out:
            params["timed_out"] = True
            return SandboxResult(
                ran=True,
                exit_code=None,
                output=output,
                error=f"sandbox_timeout: command exceeded {timeout}s",
                params=params,
            )
        return SandboxResult(ran=True, exit_code=exit_code, output=output, params=params)
    except Exception as e:  # noqa: BLE001
        return SandboxResult(
            ran=False,
            error=f"sandbox_unavailable: container run failed ({e})",
            params={**params, "runtime": "unavailable"},
        )
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
        if tmp_ws and Path(tmp_ws).exists():
            shutil.rmtree(tmp_ws, ignore_errors=True)
