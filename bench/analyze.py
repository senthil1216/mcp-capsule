"""Turn replay results into bench/REPORT.md.

Claim discipline (spec §7): report only MEASURED values. Metrics that depend on a
later milestone (e.g. exfil containment needs the Milestone D sandbox; utility /
overhead need legitimate tasks in Milestone G) are shown as "not yet measured",
never as a fabricated number.
"""

from __future__ import annotations

from statistics import median

from capsule.models import AttackReplayResult

_SECRET_KINDS = {"secret_read", "symlink_escape", "path_traversal"}
_NA = "not yet measured"


def _rate(numer: int, denom: int) -> str:
    if denom == 0:
        return "n/a"
    return f"{numer}/{denom} ({100 * numer / denom:.0f}%)"


def _percentile(values: list[int], pct: float) -> int | None:
    if not values:
        return None
    s = sorted(values)
    if pct == 50:
        return int(median(s))
    k = max(0, min(len(s) - 1, int(round((pct / 100) * (len(s) - 1)))))
    return s[k]


def build_report(results: list[AttackReplayResult], modes: list[str]) -> str:
    unsafe = [r for r in results if r.mode == "unsafe" and r.kind != "legitimate"]
    safe = [r for r in results if r.mode == "safe" and r.kind != "legitimate"]
    legit = [r for r in results if r.kind == "legitimate"]
    by_attack: dict[str, dict[str, AttackReplayResult]] = {}
    for r in results:
        if r.kind == "legitimate":
            continue
        by_attack.setdefault(r.attack, {})[r.mode] = r

    lines: list[str] = []
    lines.append("# Capsule — Benchmark Report")
    lines.append("")
    lines.append(
        "> Measured on a local run against a disposable environment with "
        "honeytokens at the real canonical secret paths. Numbers are "
        "measured, not asserted; metrics requiring a later milestone are "
        "marked *not yet measured*."
    )
    lines.append("")
    lines.append(f"Modes run: {', '.join(modes)}")
    lines.append("")

    # --- metrics ---
    secret_attacks_unsafe = [r for r in unsafe if r.kind in _SECRET_KINDS]
    secret_attacks_safe = [r for r in safe if r.kind in _SECRET_KINDS]
    reach_unsafe = sum(1 for r in secret_attacks_unsafe if r.host_secret_visible)
    reach_safe = sum(1 for r in secret_attacks_safe if r.host_secret_visible)

    net_unsafe = [r for r in unsafe if r.kind == "network_exfil"]
    net_safe = [r for r in safe if r.kind == "network_exfil"]
    exfil_attempts = sum(1 for r in net_unsafe if r.network_attempted)
    exfil_blocked_measured = [r for r in net_safe if r.network_blocked is not None]
    exfil_blocked = sum(1 for r in exfil_blocked_measured if r.network_blocked)

    tainted_safe = [r for r in safe if r.tainted_outbound]
    tainted_handled = sum(1 for r in tainted_safe if r.tainted_handled)

    # Re-encoded / chunked taint variants (Milestone E): classified by the
    # `variant=` tag the runner stamps, so a decode *failure* still counts in the
    # denominator rather than silently dropping out.
    reencoded = [
        r for r in tainted_safe if "variant=" in (r.note or "") and "variant=verbatim" not in r.note
    ]
    reencoded_caught = sum(1 for r in reencoded if r.tainted_handled)

    lines.append("## Metrics")
    lines.append("")
    lines.append(f"- `attack_count`: {len(by_attack)}")
    if secret_attacks_unsafe:
        lines.append(
            f"- `secret_reach_rate_unsafe`: {_rate(reach_unsafe, len(secret_attacks_unsafe))}"
        )
    if secret_attacks_safe:
        lines.append(f"- `secret_reach_rate_safe`: {_rate(reach_safe, len(secret_attacks_safe))}")
    elif "safe" not in modes:
        lines.append(f"- `secret_reach_rate_safe`: {_NA} (safe mode not run)")
    lines.append(f"- `network_exfil_attempts`: {exfil_attempts}")
    if exfil_blocked_measured:
        lines.append(
            f"- `network_exfil_blocked`: {_rate(exfil_blocked, len(exfil_blocked_measured))}"
        )
    else:
        lines.append(f"- `network_exfil_blocked`: {_NA} (needs the Milestone D sandbox)")
    if tainted_safe:
        lines.append(f"- `tainted_outbound_attempts`: {len(tainted_safe)}")
        lines.append(
            f"- `tainted_outbound_flagged_or_blocked`: {_rate(tainted_handled, len(tainted_safe))}"
        )
        if reencoded:
            lines.append(
                f"- `reencoded_taint_caught`: {_rate(reencoded_caught, len(reencoded))} "
                "(base64 / hex / chunked variants — content taint that survives re-encoding)"
            )
    else:
        lines.append(f"- `tainted_outbound_attempts`: {_NA} (Milestone E)")
    if legit:
        passed_legit = sum(1 for r in legit if r.passed)
        false_denies = sum(1 for r in legit if r.actual_decision == "deny")
        lines.append(f"- `allowed_task_success_rate`: {_rate(passed_legit, len(legit))}")
        lines.append(f"- `false_denies`: {false_denies}")
    else:
        lines.append(
            f"- `allowed_task_success_rate`: {_NA} (run safe mode for the legitimate corpus)"
        )
        lines.append(f"- `false_denies`: {_NA} (run safe mode for the legitimate corpus)")

    if safe and unsafe:
        overhead = []
        for modes_map in by_attack.values():
            if "safe" in modes_map and "unsafe" in modes_map:
                overhead.append(
                    max(0, modes_map["safe"].duration_ms - modes_map["unsafe"].duration_ms)
                )
        p50 = _percentile(overhead, 50)
        p95 = _percentile(overhead, 95)
        lines.append(
            f"- `p50_overhead_ms`: {p50 if p50 is not None else _NA} "
            "(median reflects gateway decision overhead; sandboxed run_command "
            "adds container-startup cost, visible at p95)"
        )
        lines.append(f"- `p95_overhead_ms`: {p95 if p95 is not None else _NA}")
    else:
        lines.append(f"- `p50_overhead_ms` / `p95_overhead_ms`: {_NA} (need both modes)")
    lines.append("")

    # --- attack result table ---
    lines.append("## Attack results")
    lines.append("")
    lines.append("| Attack | Unsafe result | Safe result | Passed |")
    lines.append("|---|---|---|---|")
    for attack in sorted(by_attack):
        m = by_attack[attack]
        u = m.get("unsafe")
        s = m.get("safe")
        unsafe_txt = _outcome(u) if u else "—"
        safe_txt = _outcome(s) if s else "—"
        passed = "yes" if (s and s.passed) else ("—" if not s else "no")
        lines.append(f"| {attack} | {unsafe_txt} | {safe_txt} | {passed} |")
    lines.append("")

    # --- two-attack insight table (the headline of the post) ---
    lines.append("## Two-attack insight")
    lines.append("")
    lines.append(
        "The point of the project: sandboxing handles the first attack "
        "class but not the second; provenance handles the second."
    )
    lines.append("")
    lines.append("| Attack type | Sandbox alone | Sandbox + provenance |")
    lines.append("|---|---|---|")
    direct = [r for r in safe if r.kind in {"secret_read", "symlink_escape", "path_traversal"}]
    direct_blocked = all(not r.host_secret_visible for r in direct) if direct else None
    taint = [r for r in safe if r.kind == "taint"]
    taint_handled = ", ".join(sorted({r.actual_decision for r in taint})) if taint else _NA
    direct_cell = (
        "blocked" if direct_blocked else (_NA if direct_blocked is None else "NOT blocked")
    )
    lines.append(f"| Direct host secret read | {direct_cell} | {direct_cell} |")
    lines.append(
        f"| Exfil via allowed outbound/write | not enough (already read) | {taint_handled} |"
    )
    lines.append("")

    # --- utility table ---
    if legit:
        lines.append("## Utility (legitimate tasks)")
        lines.append("")
        lines.append("| Legitimate task | Decision | Result |")
        lines.append("|---|---|---|")
        for r in sorted(legit, key=lambda x: x.attack):
            result_txt = "allowed" if r.passed else f"DENIED ({r.actual_decision})"
            if r.note:
                result_txt += f" — {r.note}"
            lines.append(f"| {r.attack} | {r.actual_decision} | {result_txt} |")
        lines.append("")

    lines.append("## Notes")
    for r in results:
        if r.note:
            lines.append(f"- {r.mode} / {r.attack}: {r.note}")
    lines.append("")
    lines.append("_Generated by `bench/analyze.py`._")
    return "\n".join(lines) + "\n"


def _outcome(r: AttackReplayResult) -> str:
    if r.kind == "network_exfil":
        if r.mode == "unsafe":
            return "reached sink" if r.host_secret_visible else "no sink hit"
        if r.network_blocked is None:
            return f"decision={r.actual_decision} (containment {_NA})"
        return "network blocked" if r.network_blocked else "reached sink"
    if r.mode == "unsafe":
        return "secret reached" if r.host_secret_visible else "not reached"
    return f"{r.actual_decision} / secret {'visible' if r.host_secret_visible else 'blocked'}"
