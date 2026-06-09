"""Shared handler registration.

CLI, MCP surface, and the bench runner all register tool handlers through here so
enforcement behaviour is identical across entry points. Handlers land milestone
by milestone (read_file in B, run_command in D, github_create_pr_stub in F).

A tool module that does not exist yet is skipped; but a module that *does* exist
and fails to import is a real error and is allowed to propagate — silently
swallowing it once hid a registration bug and fell back to the stub handler.
"""

from __future__ import annotations

import importlib
import importlib.util

from capsule.gateway import Gateway

# tool name -> (module, attribute)
_HANDLER_SPECS = [
    ("read_file", "tools.read_file", "read_file_handler"),
    ("run_command", "tools.run_command", "run_command_handler"),
    ("github_create_pr_stub", "tools.github_pr_stub", "github_pr_stub_handler"),
]


def register_default_handlers(gateway: Gateway) -> None:
    for tool, module_name, attr in _HANDLER_SPECS:
        if importlib.util.find_spec(module_name) is None:
            continue  # not implemented yet — gateway falls back to a safe stub
        module = importlib.import_module(module_name)
        gateway.register_handler(tool, getattr(module, attr))
