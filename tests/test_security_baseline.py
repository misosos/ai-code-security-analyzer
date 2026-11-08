"""Actual CLI evaluation of the local baseline on labeled synthetic samples."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


FIXTURES = Path(__file__).parent / "fixtures" / "security_baseline"
RULE_TEST_FIXTURE = Path(__file__).parent / "fixtures" / "dynamic_eval_rule_test" / "dynamic-eval.js"
RULES = Path(__file__).resolve().parents[1] / "rules" / "security-baseline.yml"

# Expected rule IDs and locations for each labeled synthetic file.
EXPECTED: dict[str, dict[str, list[tuple[int, str, str, str]]]] = {
    "positive": {
        "dynamic.js": [(2, "baseline.javascript-dynamic-eval", "high", "CWE-95")],
        "dynamic.ts": [
            (2, "baseline.javascript-dynamic-eval", "high", "CWE-95"),
            (6, "baseline.javascript-dynamic-eval", "high", "CWE-95"),
        ],
        "react.jsx": [(2, "baseline.react-dangerous-html", "medium", "CWE-79")],
        "react.tsx": [(2, "baseline.react-dangerous-html", "medium", "CWE-79")],
        "firestore.rules": [
            (5, "baseline.firestore-unconditional-write", "high", "CWE-284"),
            (8, "baseline.firestore-unconditional-write", "high", "CWE-284"),
        ],
    },
    "negative": {
        "dynamic.js": [],
        "dynamic.ts": [],
        "react.jsx": [],
        "react.tsx": [],
        "firestore.rules": [],
    },
}


def _scan(source: Path, target: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
    target.mkdir()
    for fixture in source.iterdir():
        shutil.copy2(fixture, target / fixture.name)
    completed = subprocess.run(
        [
            sys.executable, "-m", "ai_code_security_analyzer", "scan",
            "--path", str(target), "--rules", str(RULES), "--format", "json",
        ],
        capture_output=True, text=True, check=False, timeout=90,
    )
    return completed, json.loads(completed.stdout)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_baseline_positive_and_negative_cli_evaluation(tmp_path: Path) -> None:
    positive_run, positive = _scan(FIXTURES / "positive", tmp_path / "positive")
    negative_run, negative = _scan(FIXTURES / "negative", tmp_path / "negative")

    assert positive_run.returncode == negative_run.returncode == 0
    assert positive_run.stderr == negative_run.stderr == ""
    for report in (positive, negative):
        assert report["schema_version"] == "1.0"
        assert report["status"] == "completed" and report["completed"] is True
        assert report["issues"] == []
        assert report["rules"]["file_name"] == RULES.name
        assert report["tool"]["name"] == "semgrep"

    expected = {
        (filename, line, rule, severity, cwe)
        for filename, cases in EXPECTED["positive"].items()
        for line, rule, severity, cwe in cases
    }
    actual = {
        (finding["file_path"], finding["line_number"], finding["rule_id"], finding["severity"], finding["cwe"])
        for finding in positive["findings"]
    }
    assert actual == expected
    assert len(positive["findings"]) == len(expected) == 7
    assert positive["summary"]["by_severity"]["high"] == 5
    assert positive["summary"]["by_severity"]["medium"] == 2
    assert all(finding["status"] == "unverified" for finding in positive["findings"])
    assert all(finding["finding_id"].startswith("semgrep:") for finding in positive["findings"])
    assert len({finding["finding_id"] for finding in positive["findings"]}) == 7

    assert negative["findings"] == []
    assert negative["summary"]["finding_count"] == 0
    assert "SYNTHETIC_BASELINE_SECRET" not in positive_run.stdout
    assert str(tmp_path) not in positive_run.stdout
    assert str(RULES.parent) not in positive_run.stdout

    # Repeating the same scan against the same files preserves finding IDs.
    repeat_run = subprocess.run(
        [
            sys.executable, "-m", "ai_code_security_analyzer", "scan",
            "--path", str(tmp_path / "positive"), "--rules", str(RULES), "--format", "json",
        ],
        capture_output=True, text=True, check=False, timeout=90,
    )
    assert repeat_run.returncode == 0, repeat_run.stderr
    repeat = json.loads(repeat_run.stdout)
    assert {
        (finding["file_path"], finding["line_number"]): finding["finding_id"]
        for finding in positive["findings"]
    } == {
        (finding["file_path"], finding["line_number"]): finding["finding_id"]
        for finding in repeat["findings"]
    }


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_dynamic_eval_native_rule_annotations(tmp_path: Path) -> None:
    """Semgrep's own ruleid/ok/todo annotations pin the dynamic-eval semantics."""
    target = tmp_path / RULE_TEST_FIXTURE.name
    shutil.copy2(RULE_TEST_FIXTURE, target)
    home = tmp_path / "home"
    home.mkdir()
    completed = subprocess.run(
        [
            "semgrep", "--test", "--metrics=off", "--disable-version-check",
            "--config", str(RULES), str(target),
        ],
        capture_output=True, text=True, check=False, timeout=120, cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
        },
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "All tests passed" in completed.stdout + completed.stderr
