"""Load the capability manifest and policy config from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from capsule.models import CapabilityManifest

# Repo root = parent of the capsule/ package dir.
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY_PATH = _REPO_ROOT / "tool_registry.yaml"
DEFAULT_POLICY_PATH = _REPO_ROOT / "policy.yaml"


def load_manifest(path: str | Path = DEFAULT_REGISTRY_PATH) -> CapabilityManifest:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return CapabilityManifest.model_validate(data)


def load_policy(path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text()) or {}
