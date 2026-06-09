"""Capsule tool handlers (read_file, run_command, github_create_pr_stub).

These are repo-level modules, registered with the gateway via
capsule.tools_loader. The gateway remains the single enforcement point; handlers
only run when a decision permits execution.
"""
