# Capsule — Roadmap

This document collects the milestones the project has shipped (A–G, v0.1) and the
planned work (H–N) that takes Capsule from a containment prototype to a complete
capability gateway. Each planned milestone is a shippable unit **and** a standalone
article in the accompanying LinkedIn series.

The spine of the plan is **H → I → J**: identity → ABAC policy → scoped authority.
That arc transforms Capsule from a *sandbox* into an *authorization* system — the
area where identity/policy expertise has the most leverage.

---

## Shipped — v0.1 (Milestones A–G)

| ID | Milestone | What it is | Where |
|---|---|---|---|
| A | Gateway + policy core | Single enforcement point (`Gateway.invoke()`), fixed decision vocabulary (`allow` · `deny` · `sandbox` · `approval_required` · `flag`), decision trace, structured audit | `capsule/gateway.py`, `capsule/policy.py`, `capsule/models.py`, `capsule/audit.py` |
| B | `read_file` + workspace boundary | Registered tool handler; workspace confinement, `..`/symlink/host-secret (`~/.ssh`, `~/.aws`, `~/.kube`, `/etc`, docker socket) denial | `tools/read_file.py`, `capsule/fsboundary.py` |
| C | Content-based taint | `read_file` registers returned text (sha256 + k-gram shingles); outbound/write args matched against the store — **fires without declared `source_refs`** | `capsule/taint.py` |
| D | Docker sandbox for `run_command` | Hardened container: `--network none`, read-only root, non-root, ephemeral workspace copy. Decision enforced at policy time; execution gated behind `CAPSULE_SANDBOX_EXEC` so the base test suite stays runtime-free | `sandbox/runner.py`, `sandbox/Dockerfile`, `tools/run_command.py` |
| E | Re-encoding-resistant taint | Speculative decode of base64/hex/URL/gzip+base64, case/whitespace normalization, bounded cross-call reassembly — measured at `reencoded_taint_caught` 4/4 | `capsule/taint.py` |
| F | Approval + scoped credential broker | Out-of-band approval queue (`capsule-approve` CLI); credential broker grants `pull_request:create`, denies `repo:admin`; approval never blocks the MCP transport | `capsule/approvals.py`, `capsule/approve.py`, `tools/github_pr_stub.py` |
| G | Apples-to-apples benchmark | Unsafe vs safe against the same disposable env; honeytokens at real canonical paths; recording sink + attributed egress control. Report is generated, not hand-typed | `bench/`, `bench/REPORT.md` |

**Measured result (`bench/REPORT.md`):** unsafe secret-reach 5/5 (100%) → safe 0/5
(0%); network exfil blocked 1/1; tainted outbound flagged/blocked 6/6; re-encoded
taint caught 4/4; 0 false denies.

**Documented deferrals (honest limits):**
- Taint is content-matching, **not** full information-flow control. Resists cheap
  *reversible* re-encodings; still evadable by *lossy/keyed* transforms (encryption
  with an attacker-held key, semantic paraphrase, steganography).
- Capsule guards only its 3 built-in tools, not arbitrary MCP servers.

---

## Planned — v0.2+ (Milestones H–N)

Each row maps an engineering milestone to its article and to the resume-relevant
competency it demonstrates.

| ID | Milestone | Engineering | Article | Demonstrates |
|---|---|---|---|---|
| **H** | Identity & principal model | Add a `Principal` (agent id, delegating human, delegated scopes, session context) to `ToolCall`; thread identity through `Gateway.invoke()` and the audit log | *"Who is calling? Bringing identity to AI agent tool calls"* | Identity fundamentals (OAuth2/OIDC, principals, delegation) |
| **I** | OPA-backed ABAC policy | Migrate the static per-tool yaml to Rego; decisions become `(principal, action, resource, env) → decision`. Same `run_command` can be `allow` for a trusted CI agent and `approval_required` for an interactive one | *"From static rules to ABAC: OPA for AI agent authorization"* | Policy engines (OPA), ABAC/RBAC (your CanCanCan→OPA migration, redux) |
| **J** | OAuth2 token-exchange broker | Replace the toy broker with real scoped, short-lived token issuance (RFC 8693 token exchange); the agent gets a token for the action, not blanket trust | *"Scoped authority for agents: OAuth2 token exchange, not blanket trust"* | Token exchange, scoped credentials, service-to-service auth (your core resume depth) |
| **K** | Authenticated approval + SoD | Approver identity; requestor ≠ approver; risk-tiered dual control for high-risk writes | *"Human-in-the-loop that actually means something: SoD for agent actions"* | Governance, segregation of duties, access controls |
| **L** | Tamper-evident audit | Hash-chained audit log; optional external witness; detect tampered/reordered entries | *"The system of record: tamper-evident audit for agent actions"* | Audit integrity, observability, compliance posture |
| **M** | Transparent MCP proxy | Discover a downstream MCP server's tools and wrap each through the gateway — Capsule guards any MCP server, not just its built-ins | *"Point Capsule at any MCP server: a real capability gateway"* | Architecture, protocol fidelity, real-world deployability |
| **N** | Detection of the un-preventable | Generic outbound DLP secret scan (agent-exfiltrated *generated* keys, not just read ones); per-session velocity/rate limits; live honeytokens in the runtime path | *"Catching what you can't prevent: detection for the taint evasions"* | Fraud/abuse detection, defense-in-depth |

**Acknowledged longer-term (not in H–N):** taint resistance to *lossy/keyed*
transforms remains fundamentally open — it requires either semantic analysis or an
information-flow-control substrate, both out of scope for v0.x.

---

## Sequencing & demo strategy

- **H → I → J is the spine.** Identity, then ABAC, then scoped authority. Each
  depends on the prior and each is a standalone article. This is where Capsule stops
  being "a sandbox with a clever taint trick" and becomes a complete authorization
  gateway.
- **Every release ships a demo + an article together.** Reproducible demo assets
  (`docs/demo.tape` via `vhs`) keep the GIFs honest as code changes; generated
  benchmark numbers (`bench/REPORT.md`) keep the claims honest.
- **The live-model injection demo** (a real LLM reading the malicious README and
  emitting the malicious calls itself) is the flagship demo — it proves the gateway
  is model-agnostic and works against genuine prompt injection. It is the prelude to
  H and the asset for the overview article.

## Versioning

- Current: `0.1.0` (Milestones A–G).
- Bump to `0.2.0` when H + I land (the identity + ABAC spine).
