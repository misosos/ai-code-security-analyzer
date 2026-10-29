from __future__ import annotations

import os
import shutil

import pytest

from tests.benchmark.phase6e.evaluate import run_evaluation


def test_phase6e_heldout_evaluation_uses_required_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    report = run_evaluation()
    assert report["metrics_available"] is True
    assert report["evaluation_set_version"] == "phase6e-heldout-synthetic-v1"
    assert report["expected_semgrep_version"] == "1.182.1"
    assert len(report["metrics_by_rule"]) == 6
    assert set(report["scan_runs"]) == {"baseline", "eval_taint", "command_injection"}
    assert all(run["scan_status"] == "completed" for run in report["scan_runs"].values())
    assert all(run["semgrep_version"] == "1.182.1" for run in report["scan_runs"].values())
    assert all(run["all_findings_unverified"] for run in report["scan_runs"].values())
    assert report["confirmed_vulnerability"] == "NOT_EVALUATED"
    # Detection errors are benchmark outcomes, not a reason to corrupt or hide scores.
    print(__import__("json").dumps(report, sort_keys=True, separators=(",", ":")))
