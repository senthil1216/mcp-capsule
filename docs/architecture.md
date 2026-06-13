# Capsule — Architecture

## One enforcement point

Every tool call — from the MCP surface, the CLI harness, or the bench runner —
flows through `Gateway.invoke()`. The MCP layer and CLI add **no** authority of
their own; they only build a `ToolCall` and hand it to the gateway.

```
   MCP client ─┐
   CLI harness ─┼──▶ ToolCall ──▶ Gateway.invoke() ──▶ ToolResult
   bench runner ┘                      │
                                       ├─ PolicyEngine        (static per-tool decision + trace)
                                       ├─ dynamic policy      (read_file workspace boundary)
                                       ├─ taint store         (content-based escalation)
                                       ├─ capability diff     (unsafe vs requested vs granted)
                                       ├─ tool handler        (only if decision permits execution)
                                       ├─ redaction           (PEM / tokens / AWS keys)
                                       ├─ approval queue       (out-of-band, on approval_required)
                                       └─ audit log           (one JSON event per call)
```

## Decision flow

1. **Static policy** (`policy.py` + `policy.yaml`): unknown tool → `deny`;
   `read_file` → `allow`; `run_command` → `sandbox`; `github_create_pr_stub` →
   `approval_required`. Produces a `DecisionTrace`.
2. **Dynamic policy**:
   - `read_file` workspace boundary (`fsboundary.py`) — escape / host-secret →
     escalate to `deny`.
   - **content-based taint** (`taint.py`) — tainted content in an outbound/write
     argument escalates: PR body → `approval_required`, network command → `deny`,
     local command → (stays `sandbox`, flagged).
   - Escalation always keeps the **more restrictive** decision
     (`deny > approval_required > sandbox > flag > allow`).
3. **Capability diff** (`diff.py`): unsafe vs requested vs granted authority.
4. **Execution**: handlers run only for `allow` / `flag` / `sandbox`.
   `approval_required` enqueues an out-of-band record; `deny` never executes.
5. **Audit** (`audit.py`): one structured `AuditEvent` per call.

## Fixed decision vocabulary

`allow` · `deny` · `sandbox` · `approval_required` · `flag` — used identically in
the engine, the `PolicyDecision.decision` field, the trace, the audit log, and all
prose. No synonyms.

## Content-based taint (the differentiator)

`read_file` registers the returned text in a per-session store as
`content_ref → text + sha256 + k-gram shingle hashes`. On any outbound/write call,
arguments are matched against the store by **substring (either direction)** or
**shingle overlap**. Enforcement fires on content; `source_refs` is an optional
hint only and is never required. Lifecycle: per-session, cleared on restart.

## Module map

| Module | Role |
|---|---|
| `capsule/models.py` | Pydantic data model (ToolCall, PolicyDecision, …) |
| `capsule/gateway.py` | The single enforcement point |
| `capsule/policy.py` | Static policy + escalation precedence |
| `capsule/fsboundary.py` | read_file workspace boundary |
| `capsule/taint.py` | Content-based taint store + matching |
| `capsule/diff.py` | Capability diff |
| `capsule/redaction.py` | Secret redaction |
| `capsule/approvals.py` + `capsule/approve.py` | Out-of-band approval queue + CLI |
| `capsule/audit.py` | Structured audit log |
| `capsule/mcp_server.py` | FastMCP tool surface |
| `tools/` | read_file, sandboxed run_command, github_pr_stub handlers |
| `sandbox/` | Docker runner: hardened container (`--network none`, read-only root, non-root, ephemeral workspace copy) + Dockerfile |
| `bench/` | honeytokens, sink, runner, analyze, corpus |
