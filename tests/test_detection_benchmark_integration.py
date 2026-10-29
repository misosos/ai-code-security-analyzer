from __future__ import annotations

import json
import os
import shutil

import pytest

from tests.benchmark.evaluate import run_benchmark


def test_independent_benchmark_runs_on_required_semgrep_oss() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    report = run_benchmark()
    assert report["metrics_available"] is True
    assert report["semgrep_expected_version"] == "1.182.1"
    assert len(report["metrics_by_rule"]) == 6
    assert all(run["scan_status"] == "completed" for run in report["scan_runs"].values())
    assert all(run["semgrep_version"] == "1.182.1" for run in report["scan_runs"].values())
    # Capture the measured outcomes for CI logs without making FP/FN counts a
    # test failure condition.
    print(
        json.dumps(
            {
                "scan_runs": report["scan_runs"],
                "metrics_by_rule": report["metrics_by_rule"],
                "unexpected_findings": report["unexpected_findings"],
                "unscored_out_of_scope_findings": report["unscored_out_of_scope_findings"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
