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
- Network exfil via shell: **blocked 1/1** — `run_command` runs in a Docker
  sandbox with `--network none`, measured against a recording sink.
- Exfil-via-outbound (paste already-read notes into a PR body, declaring no
  provenance): **6/6 flagged or blocked** — `approval_required` for the PR body,
  `deny` for the network command, including base64 / hex / chunked variants.
- Re-encoded exfil (base64, hex, split-across-calls): **4/4 caught** — content
  taint that survives the cheap reversible evasions (Milestone E).
- Legitimate tasks: **0 false denies**.

(The network-exfil block is *attributed*, not assumed: an egress control posts a
token from a networked container — which arrives — and from a `--network none`
container — which doesn't. So "no sink hit" is a real network block, not an
unreachable-address artifact. Container startup shows up as the `p95` overhead.)

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

It also sees through the cheap evasions an exfil script reaches for first:
base64 / hex / URL-encoding and gzip+base64 are speculatively decoded, case and
whitespace are normalized away, and a secret dribbled out across several calls is
caught by reassembling a bounded per-session buffer (Milestone E, measured 4/4).

Honest limit: this is still minimal provenance by content matching, **not** full
information-flow control. It's defeated by *lossy or keyed* transforms —
encryption with a key you don't hold, a genuine paraphrase, steganography —
because the secret is no longer recoverable from what crosses the boundary. That's
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
- Not "taint tracking is complete" — it's minimal provenance. It resists cheap
  *reversible* re-encodings (base64/hex/URL/gzip, case/whitespace, cross-call
  chunking) but is still evadable by lossy or keyed transforms (encryption,
  paraphrase).

## Allowed claims

- MCP tools should be treated as capabilities.
- Runtime controls reduce the blast radius of prompt-influenced tool calls.
- On this local corpus, Capsule reduced measured secret reach from 100% (unsafe) to
  0% (safe).
- On this corpus, network exfil via the sandboxed shell was blocked 1/1, with the
  block attributed by an egress control (networked=reachable, --network none=blocked).
- Content taint survives the cheap reversible evasions: base64 / hex / chunked
  exfil were caught 4/4 (`reencoded_taint_caught`).
- Provenance is needed because sandboxing alone doesn't address data that was
  already legitimately read and later sent to outbound/write tools.
- Approval and scoped credentials are separate from container isolation.
- This is a prototype, not a production multi-tenant sandbox.

## Repo

`mcp-capsule` — gateway, MCP surface, re-encoding-resistant content taint,
approval + broker, apples-to-apples benchmark. `make test` (66 tests),
`make test-docker` (sandbox integration), `make bench`, `make demo`.
