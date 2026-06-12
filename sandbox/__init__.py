"""Capsule sandbox runtime (Milestone D).

Hosts the Docker-backed runner that executes run_command inside a hardened,
network-isolated container. Importing this package never imports the docker SDK;
the runner imports it lazily so the gateway stays usable on machines without a
container runtime.
"""
