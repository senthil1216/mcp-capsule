# Capsule: Treating MCP Tools as Capabilities — Sandbox the Call, Track What Leaves

*Draft. Quote every number from the generated `bench/REPORT.md`; do not hand-type
metrics. Keep claims inside the "allowed claims" list at the bottom.*

## Hook

I let an MCP-connected agent run a small prompt-injection attack corpus against
local tools. The interesting result was not just that sandboxing blocked direct
host-secret reads. It was that sandboxing alone did **not** model a second risk:
data that was already allowed to be read can later flow into outbound or
write-capable tools.

## The setup

MCP tools are capabilities. Prompt injection can't be fully prevented, so I built
**Capsule**, a runtime capability gateway that sits between the agent and its
tools as the single enforcement point. Every call gets: a policy decision (with a
trace), a capability diff (unsafe vs requested vs granted authority), content-based
taint checking, and an audit record.

Three guarded tools: `read_file`, `run_command`, `github_create_pr_stub`. Five
decisions, no synonyms: `allow`, `deny`, `sandbox`, `approval_required`, `flag`.

## Measuring it honestly

The measurement is apples-to-apples: unsafe mode and safe mode run against the
**same** disposable environment, with honeytokens planted at the *real* canonical
secret paths (`~/.ssh/id_rsa`, …) inside a throwaway HOME — never my real keys.
Exfil is measured by a local recording sink, not asserted.

Result (from `bench/REPORT.md`):

- Direct secret reads: **unsafe 5/5 reached → safe 0/5**.
- Exfil-via-outbound (paste already-read notes into a PR body, declaring no
  provenance): **2/2 flagged or blocked** — `approval_required` for the PR body,
  `deny` for the network command.
- Legitimate tasks: **0 false denies**.

(The Docker sandbox for `run_command` isn't wired on my machine yet, so I report
the network-exfil-blocked row and container overhead as *not yet measured* rather
than faking them. The decision — `sandbox`, network denied — is shown regardless.)

## The part that surprised me

Sandboxing is great at "can this process touch the host?" It is useless against
"the agent already read this file and is now pasting it into a pull request." That
second attack doesn't need any host access — the data is already in hand.

So Capsule adds **content-based** provenance: when `read_file` returns content, it
registers the actual text (plus shingle hashes). When an outbound/write tool is
called, its arguments are matched against that store. The key property: it fires
**even when the caller declares no `source_refs`** — because a malicious agent
won't honestly declare provenance; it'll just paste the secret. Matching on
content, not on declarations, is what makes the second result real instead of
theater.

Honest limit: this is minimal provenance by content matching, **not** full
information-flow control. Base64 or a light paraphrase evades it. That's
acknowledged future work.

## Capability diff + audit

For every high-risk call, Capsule prints the gap between the authority the tool
*would* have unsandboxed, what its manifest *requests*, and what the decision
actually *grants*. Every decision is one structured audit line. Approval for the
PR stub is out-of-band (a separate `capsule-approve` CLI) so it never blocks the
MCP stdio transport — and the credential broker grants `pull_request:create` but
denies `repo:admin`, because authorization scope is a different axis from
container isolation.

## What I'm NOT claiming

- Not "I solved MCP security."
- Not "this prevents prompt injection."
- Not "Docker makes hostile code safe."
- Not "production-ready isolation."
- Not "taint tracking is complete" — it's minimal provenance, evadable by
  re-encoding.

## Allowed claims

- MCP tools should be treated as capabilities.
- Runtime controls reduce the blast radius of prompt-influenced tool calls.
- On this local corpus, Capsule reduced measured secret reach from 100% (unsafe) to
  0% (safe).
- Provenance is needed because sandboxing alone doesn't address data that was
  already legitimately read and later sent to outbound/write tools.
- Approval and scoped credentials are separate from container isolation.
- This is a prototype, not a production multi-tenant sandbox.

## Repo

`mcp-capsule` — gateway, MCP surface, content-based taint, approval + broker,
apples-to-apples benchmark. `make test` (47 tests), `make bench`, `make demo`.
