"""Bench harness tests (Milestone C): honeytokens, sink, unsafe vs safe."""

import os
import tempfile
import urllib.request
from pathlib import Path

from bench import honeytokens
from bench.runner import run
from bench.sink import RecordingSink


def test_honeytokens_disposable_and_sentineled():
    real_home = os.environ.get("HOME")
    with tempfile.TemporaryDirectory() as d:
        env = honeytokens.setup(d)
        # Files exist at canonical sub-paths with their sentinels.
        assert env.path("ssh").exists()
        assert env.sentinels["ssh"] in env.path("ssh").read_text()
        assert env.sentinels["aws"] in env.path("aws").read_text()
        # Disposable home is NOT the developer's real home.
        assert str(env.home) != (real_home or "")
        honeytokens.teardown(d)
        assert not env.path("ssh").exists()
    # The runner never mutated the real HOME at module import time.
    assert os.environ.get("HOME") == real_home


def test_sink_records_hits():
    with RecordingSink() as sink:
        urllib.request.urlopen(f"{sink.url}/collect", data=b"SECRET-PAYLOAD-XYZ", timeout=5)
        assert sink.hits, "sink should record the POST"
        assert sink.hits_containing("SECRET-PAYLOAD-XYZ")


def test_unsafe_reaches_and_safe_denies_read_attacks():
    real_home = os.environ.get("HOME")
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / "REPORT.md"
        results = run(
            ["unsafe", "safe"],
            attacks=["read_host_ssh_key", "read_aws_credentials"],
            report_path=report,
        )
        unsafe = {r.attack: r for r in results if r.mode == "unsafe"}
        safe = {r.attack: r for r in results if r.mode == "safe"}

        # Unsafe baseline reproduces the attack (secret reached).
        assert unsafe["read_host_ssh_key"].host_secret_visible
        assert unsafe["read_aws_credentials"].host_secret_visible
        # Safe mode denies and the secret is never visible.
        assert safe["read_host_ssh_key"].actual_decision == "deny"
        assert not safe["read_host_ssh_key"].host_secret_visible
        assert safe["read_aws_credentials"].actual_decision == "deny"
        assert report.exists()
        assert "not asserted" in report.read_text()
    # HOME restored after the run.
    assert os.environ.get("HOME") == real_home
