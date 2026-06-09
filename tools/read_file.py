"""read_file tool handler.

read_file is a taint *source*: every successful read registers the returned text
in the gateway's taint store (tagged untrusted_repo_content) and returns a
content_ref alongside the content. The workspace boundary itself is enforced as
policy in capsule.fsboundary / Gateway (an out-of-workspace or host-secret read
becomes a `deny` before this handler ever runs); the handler re-validates
defensively and reads.
"""

from __future__ import annotations

import os
from pathlib import Path

from capsule.fsboundary import classify_read_path
from capsule.gateway import Gateway, HandlerOutput
from capsule.models import ToolCall

# Cap returned content so a huge file can't blow up the audit log / transport.
MAX_BYTES = 256 * 1024


def read_file_handler(call: ToolCall, gateway: Gateway) -> HandlerOutput:
    requested = call.arguments.get("path")
    if not requested:
        return HandlerOutput(ok=False, error="read_file:no_path")

    workspace = call.workspace or os.getcwd()
    verdict = classify_read_path(workspace, str(requested))
    if not verdict.allowed:
        # Defense in depth — the gateway should already have denied this.
        return HandlerOutput(ok=False, error=f"read_file:{verdict.reason}")

    target: Path = verdict.resolved  # type: ignore[assignment]
    if not target.exists() or not target.is_file():
        return HandlerOutput(ok=False, error="read_file:not_found")

    try:
        data = target.read_bytes()[:MAX_BYTES]
        content = data.decode("utf-8", errors="replace")
    except OSError as e:
        return HandlerOutput(ok=False, error=f"read_file:io_error:{e}")

    # Register the actual content in the taint store — this is what later lets
    # the gateway catch the secret flowing into an outbound/write tool, even if
    # the caller declares no source_refs.
    rel = os.path.relpath(target, Path(workspace).resolve())
    label = gateway.taint.register(content, source_type="repo_file", path=rel)

    return HandlerOutput(
        ok=True,
        output=content,
        content_ref=label.content_ref,
        taint=label,
    )
