# Capsule sandbox image (Milestone D).
#
# A minimal, non-root execution environment for run_command. It carries just
# enough to run the corpus faithfully — python (for legitimate tasks and egress
# probes) and curl (the shape the exfil attacks actually use) — and nothing that
# would let a sandboxed process touch the host. Network isolation, capability
# drop, and the read-only root filesystem are applied by the runner at launch
# (sandbox/runner.py), not baked here.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root by construction. The runner also passes user=, cap_drop=ALL,
# no-new-privileges, and read_only=True; this is defense in depth.
RUN useradd --create-home --uid 1000 capsule
USER capsule
WORKDIR /workspace

# Sandboxed commands are passed via `sh -c` at launch; no default entrypoint
# work is needed.
CMD ["sleep", "0"]
