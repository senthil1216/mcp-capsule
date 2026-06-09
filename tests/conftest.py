"""Test isolation: redirect Capsule's default runtime-artifact paths to a temp
dir so tests never write audit.log / pending_approvals.jsonl into the repo and
never contaminate each other.
"""

import pytest

from capsule import approvals as approvals_mod
from capsule import audit as audit_mod


@pytest.fixture(autouse=True)
def _isolate_runtime_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_mod, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
    monkeypatch.setattr(
        approvals_mod, "DEFAULT_APPROVAL_PATH", tmp_path / "pending_approvals.jsonl"
    )
    yield
