"""Workspace filesystem boundary for read_file.

This is policy, not just handler hygiene: a read that escapes the workspace or
targets a host-secret path must become a `deny` decision (visible in the trace
and audit), so the logic lives here and is shared by the gateway (to set the
decision) and the read_file handler (to actually read).

Resolution follows symlinks via Path.resolve(), so a symlink inside the
workspace that points at ~/.ssh is caught: the resolved target lands outside the
workspace / inside a secret root and is denied.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Canonical host-secret roots the attack corpus targets. Denied even if a
# symlink inside the workspace resolves into one of them.
HOST_SECRET_ROOTS = [
    "~/.ssh",
    "~/.aws",
    "~/.kube",
    "/etc",
    "/var/run/docker.sock",
]


@dataclass
class PathVerdict:
    allowed: bool
    reason: str
    resolved: Path | None


def _expanded_secret_roots() -> list[Path]:
    roots: list[Path] = []
    for r in HOST_SECRET_ROOTS:
        try:
            roots.append(Path(os.path.expanduser(r)).resolve())
        except OSError:
            roots.append(Path(os.path.expanduser(r)))
    return roots


def _under(target: Path, root: Path) -> bool:
    return target == root or root in target.parents


def classify_read_path(workspace_root: str | os.PathLike, requested: str) -> PathVerdict:
    """Classify a requested read path relative to the workspace root."""
    root = Path(workspace_root).resolve()
    expanded = os.path.expanduser(str(requested))

    if os.path.isabs(expanded):
        target = Path(expanded)
    else:
        target = root / requested

    # Resolve symlinks / .. so the *real* destination is what we judge.
    try:
        resolved = target.resolve()
    except OSError:
        resolved = target

    # 1. Host-secret roots first (clearest, highest-signal denial).
    for secret_root in _expanded_secret_roots():
        if _under(resolved, secret_root):
            return PathVerdict(False, "host_secret_path", resolved)

    # 2. Must stay inside the workspace.
    if not _under(resolved, root):
        return PathVerdict(False, "path_escapes_workspace", resolved)

    return PathVerdict(True, "within_workspace", resolved)
