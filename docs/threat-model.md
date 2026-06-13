# Capsule — Threat Model

## Trust boundary (foundational — read first)

**The agent's only host capability is Capsule's MCP tool surface.** The agent has
no other shell, filesystem, or network access. Every action it can take on the
host is a Capsule tool call, and every tool call passes through
`Gateway.invoke()`.

This assumption is load-bearing. If the agent is, say, a coding agent that also
has its own unrestricted shell, Capsule is pointless — the agent would simply
bypass it. Capsule is meaningful only when it is the *sole* path from the agent to
the host.

## What Capsule is

A runtime capability gateway. It treats each MCP tool as a scoped capability and,
for every call, applies: policy, least privilege, sandboxing (for shell), scoped
authority (for the PR stub), content-based provenance, and audit.

## Adversary

A prompt-injected agent. Untrusted content (e.g. a repository README) instructs
the agent to misuse its tools: read host secrets, exfiltrate data over the
network, or smuggle already-read secrets into an outbound/write tool. We assume
prompt injection *cannot be fully prevented*, so we focus on containing the blast
radius of the resulting tool calls.

## What Capsule protects against

- **Direct host-secret reads.** `read_file` is confined to the workspace; absolute
  paths outside it, `..` traversal, symlink escape, and canonical secret paths
  (`~/.ssh`, `~/.aws`, `~/.kube`, `/etc`, the docker socket) are denied. *Measured:
  unsafe 100% reach → safe 0%.*
- **Network exfil via shell.** `run_command` runs in a Docker sandbox with
  `--network none`, a read-only root, a non-root user, and an ephemeral copy of
  the workspace (Milestone D). The decision (`sandbox`, network denied) is enforced
  at policy time regardless of runtime; containment is *measured* by the bench
  against a recording sink, with an egress-attribution control proving the sink is
  reachable when networking is allowed. *Measured: network exfil blocked 1/1.*
- **Exfil of already-read data via outbound/write tools.** Content-based taint:
  text returned by `read_file` is registered; if it later appears in a PR body or
  a network-bound command, the call is flagged / requires approval / is denied —
  **even when the caller declares no `source_refs`.**
- **Over-broad authority on writes.** The PR stub's credential broker grants only
  `pull_request:create`; broader scopes (e.g. `repo:admin`) are denied. Approval is
  out-of-band and never blocks the MCP transport.

## What Capsule does NOT protect against (non-goals / honest limits)

- **Docker is not a hard isolation boundary.** Container escape, kernel exploits,
  and side channels are out of scope. Capsule reduces blast radius; it is not a
  hardened multi-tenant sandbox.
- **Taint is content-matching, not full information-flow control.** Matching is by
  substring / shingle-hash on the actual content. Milestone E hardens it against
  the cheap *reversible* evasions — base64 / hex / URL-encoding and gzip+base64
  (speculative decode), case/whitespace mangling (normalization), and a secret
  split across multiple calls (bounded per-session reassembly); measured at
  `reencoded_taint_caught` 4/4. It remains **evadable by lossy or keyed
  transforms** — encryption with an attacker-held key, semantic paraphrase /
  summarization, steganography — because the bytes no longer derive recoverably
  from the secret. This is acknowledged future work, not a solved problem.
- **MCP fidelity limits.** Capsule exposes a representative tool surface, not a
  transparent proxy for arbitrary MCP servers.
- **Not production-ready.** v0.1 is a prototype to demonstrate the architecture and
  produce a measured result.

## Why approval is separate from sandboxing

Container isolation answers "can this process touch the host?" Approval and scoped
credentials answer "is this *write* authorized, and at what scope?" They are
orthogonal axes: a perfectly sandboxed process can still be used to open a
malicious PR. Capsule models both.
