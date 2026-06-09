"""read_file workspace-boundary + taint-source tests (Milestone B)."""

import os
import tempfile
from pathlib import Path

import pytest

from capsule.fsboundary import classify_read_path
from capsule.gateway import Gateway
from capsule.models import Decision, ToolCall
from capsule.tools_loader import register_default_handlers


@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "README.md").write_text("# hello\nworkspace file content\n")
        (root / "sub").mkdir()
        (root / "sub" / "note.txt").write_text("nested note")
        yield root


@pytest.fixture
def gateway(workspace):
    gw = Gateway(audit_path=workspace / "audit.log")
    register_default_handlers(gw)
    return gw


def _read(gw, workspace, path):
    return gw.invoke(
        ToolCall(
            call_id="r",
            tool="read_file",
            arguments={"path": path},
            workspace=str(workspace),
        )
    )


# --- boundary classification (pure) ---------------------------------------
def test_classify_within_workspace(workspace):
    v = classify_read_path(workspace, "README.md")
    assert v.allowed and v.reason == "within_workspace"


def test_classify_traversal_denied(workspace):
    v = classify_read_path(workspace, "../../../../../../etc/passwd")
    assert not v.allowed
    assert v.reason in {"host_secret_path", "path_escapes_workspace"}


def test_classify_absolute_outside_denied(workspace):
    v = classify_read_path(workspace, "/tmp")
    assert not v.allowed


def test_classify_host_secret_tilde(workspace):
    v = classify_read_path(workspace, "~/.ssh/id_rsa")
    assert not v.allowed and v.reason == "host_secret_path"


def test_classify_symlink_escape_denied(workspace):
    # A symlink inside the workspace pointing at a host-secret dir is caught
    # because resolve() follows it to the real (out-of-workspace) destination.
    link = workspace / "evil_link"
    try:
        os.symlink(os.path.expanduser("~/.ssh"), link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    v = classify_read_path(workspace, "evil_link/id_rsa")
    assert not v.allowed


# --- gateway-level behaviour ----------------------------------------------
def test_read_file_within_workspace_allows_and_taints(gateway, workspace):
    result = _read(gateway, workspace, "README.md")
    assert result.decision == Decision.ALLOW
    assert result.ok
    assert "workspace file content" in result.output
    assert result.content_ref
    assert result.taint.taint == "untrusted_repo_content"
    # The content is now registered in the taint store.
    assert gateway.taint.is_tainted("workspace file content")


def test_read_file_host_secret_denied(gateway, workspace):
    result = _read(gateway, workspace, "~/.ssh/id_rsa")
    assert result.decision == Decision.DENY
    assert not result.ok
    assert "host_secret_path" in result.error


def test_read_file_traversal_denied(gateway, workspace):
    result = _read(gateway, workspace, "../../../../etc/passwd")
    assert result.decision == Decision.DENY
    assert not result.ok


def test_read_file_missing_file(gateway, workspace):
    result = _read(gateway, workspace, "does_not_exist.md")
    # Path is in-workspace (allowed) but the file isn't there.
    assert result.decision == Decision.ALLOW
    assert not result.ok
    assert "not_found" in result.error
