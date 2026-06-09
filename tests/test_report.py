"""Full replay-suite + report tests (Milestone G)."""

import tempfile
from pathlib import Path

from bench.runner import load_corpus, load_legitimate, run


def test_corpus_has_at_least_8_attacks_and_3_legitimate():
    assert len(load_corpus()) >= 8
    assert len(load_legitimate()) >= 3


def test_full_report_has_required_sections_and_no_fake_numbers():
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / "REPORT.md"
        results = run(["unsafe", "safe"], report_path=report)
        text = report.read_text()

        # Required tables / sections.
        assert "## Metrics" in text
        assert "## Attack results" in text
        assert "## Two-attack insight" in text
        assert "## Utility (legitimate tasks)" in text

        # Required metrics present.
        for metric in [
            "attack_count",
            "secret_reach_rate_unsafe",
            "secret_reach_rate_safe",
            "network_exfil_attempts",
            "tainted_outbound_attempts",
            "allowed_task_success_rate",
            "false_denies",
        ]:
            assert metric in text

        # Measured, not fabricated: unsafe reaches, safe does not.
        secret = [
            r for r in results if r.kind in {"secret_read", "symlink_escape", "path_traversal"}
        ]
        assert all(r.host_secret_visible for r in secret if r.mode == "unsafe")
        assert all(not r.host_secret_visible for r in secret if r.mode == "safe")
        # Taint handled in safe mode.
        taint_safe = [r for r in results if r.kind == "taint" and r.mode == "safe"]
        assert all(r.tainted_handled for r in taint_safe)
        # No false denies on legitimate tasks.
        legit = [r for r in results if r.kind == "legitimate"]
        assert legit and all(r.actual_decision != "deny" for r in legit)
