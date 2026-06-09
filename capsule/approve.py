"""`capsule-approve` — the out-of-band approval CLI.

The gateway never blocks on approval; it enqueues a pending record. This CLI is
the human-in-the-loop release valve, run as a separate process:

    capsule-approve list
    capsule-approve approve appr_001_xyz
    capsule-approve deny appr_001_xyz

On approve, the credential broker is consulted for the requested scope. Only if
the broker grants the scope is the PR event actually written. A denied approval
(or a broker-denied over-broad scope) produces no event.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from capsule.approvals import DEFAULT_APPROVAL_PATH, ApprovalQueue
from capsule.audit import AuditLog, now_iso
from capsule.models import AuditEvent, Decision
from tools.github_pr_stub import broker_request, execute_pr


def _audit(state: str, record, granted_scope, event_ref, reason) -> None:
    AuditLog().emit(
        AuditEvent(
            timestamp=now_iso(),
            call_id=record.call_id,
            tool=record.tool,
            decision=Decision.APPROVAL_REQUIRED,
            reasons=[f"approval_{state}"],
            taint_flags=record.taint_flags,
            approval_state=state,
            granted_scope=granted_scope,
            ok=state == "approved",
            error=None if state == "approved" else reason,
        )
    )


def cmd_list(queue: ApprovalQueue) -> int:
    pending = queue.list_pending()
    if not pending:
        print("No pending approvals.")
        return 0
    for r in pending:
        taint = f"  taint={r.taint_flags}" if r.taint_flags else ""
        print(f"{r.id}  tool={r.tool}  scope={r.requested_scope}  title={r.title!r}{taint}")
    return 0


def cmd_approve(queue: ApprovalQueue, approval_id: str, events_path: Path | None) -> int:
    record = queue.get(approval_id)
    if record is None or record.state != "pending":
        print(f"No pending approval with id {approval_id}")
        return 1

    # Scope is a SEPARATE axis: the broker can deny even an approved request.
    broker = broker_request(record.tool, record.requested_scope)
    if not broker.granted:
        queue.resolve(
            approval_id, state="denied", granted_scope=None, event_ref=None, reason=broker.reason
        )
        _audit("denied", record, None, None, broker.reason)
        print(f"DENIED by credential broker: {broker.reason}. No event written.")
        return 1

    event_ref = execute_pr(
        title=record.title,
        body=record.body,
        granted_scope=broker.scope,
        events_path=events_path or _default_events(),
    )
    queue.resolve(
        approval_id,
        state="approved",
        granted_scope=broker.scope,
        event_ref=event_ref,
        reason="scoped_grant",
    )
    _audit("approved", record, broker.scope, event_ref, "scoped_grant")
    print(f"APPROVED. Scope granted: {broker.scope}. Event: {event_ref}")
    return 0


def cmd_deny(queue: ApprovalQueue, approval_id: str) -> int:
    record = queue.get(approval_id)
    if record is None or record.state != "pending":
        print(f"No pending approval with id {approval_id}")
        return 1
    queue.resolve(
        approval_id, state="denied", granted_scope=None, event_ref=None, reason="human_denied"
    )
    _audit("denied", record, None, None, "human_denied")
    print(f"DENIED. No event written for {approval_id}.")
    return 0


def _default_events():
    from tools.github_pr_stub import DEFAULT_EVENTS_PATH

    return DEFAULT_EVENTS_PATH


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capsule-approve")
    parser.add_argument("action", choices=["list", "approve", "deny"])
    parser.add_argument("approval_id", nargs="?")
    parser.add_argument("--queue", default=str(DEFAULT_APPROVAL_PATH))
    parser.add_argument("--events", default=None)
    args = parser.parse_args(argv)

    queue = ApprovalQueue(args.queue)
    if args.action == "list":
        return cmd_list(queue)
    if not args.approval_id:
        parser.error("approve/deny require an approval_id")
    events_path = Path(args.events) if args.events else None
    if args.action == "approve":
        return cmd_approve(queue, args.approval_id, events_path)
    return cmd_deny(queue, args.approval_id)


if __name__ == "__main__":
    sys.exit(main())
