"""Required Semgrep 1.182.1 OSS taint PoC on synthetic fixtures only."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import (
    MAX_OUTPUT_BYTES,
    SCAN_TIMEOUT_SECONDS,
    ScanStatus,
    SemgrepAdapter,
    _run_process,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "semgrep_taint"
TRUSTED_RULES = ROOT / "rules"
TAINT_RULE = TRUSTED_RULES / "experimental" / "javascript-eval-taint.yml"
BASELINE_RULE = TRUSTED_RULES / "security-baseline.yml"
REQUIRED_VERSION = "1.182.1"
CANARY = "SYNTHETIC_TAINT_CANARY_ONLY"

# Expected sink lines for a source-to-sink relation within the OSS PoC scope.
EXPECTED_PLAIN_TAINT = {
    "A_direct.js": 2,
    "B_assignment.js": 3,
    "C_multistep.ts": 5,
    "F_unknown_sanitizer.ts": 3,
    "G_modeled_sanitizer.js": 3,
    "H_partial_condition.js": 4,
    "K_nested_conditions.ts": 8,
}
EXPECTED_MODELED_SANITIZER = {
    "A_direct.js": 2,
    "B_assignment.js": 3,
    "C_multistep.ts": 5,
    "F_unknown_sanitizer.ts": 3,
    "H_partial_condition.js": 4,
    "K_nested_conditions.ts": 8,
}
EXPECTED_BASELINE = {
    "A_direct.js": 2,
    "B_assignment.js": 3,
    "C_multistep.ts": 5,
    "D_constant.js": 3,
    "E_unrelated.js": 4,
    "F_unknown_sanitizer.ts": 3,
    "G_modeled_sanitizer.js": 3,
    "H_partial_condition.js": 4,
    "I_function_boundary.js": 6,
    "J_split_sink.js": 2,
    "K_nested_conditions.ts": 8,
}


def _require_semgrep() -> str:
    executable = shutil.which("semgrep")
    if executable is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    with tempfile.TemporaryDirectory(prefix="semgrep-version-home-") as home_value:
        home = Path(home_value)
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        result = _run_process([executable, "--version"], ROOT, env, 10)
    version = result.stdout.decode("utf-8", errors="replace").strip()
    if result.exit_code != 0 or version != REQUIRED_VERSION:
        pytest.fail("unexpected_semgrep_version")
    return executable


def _copy_fixtures(target: Path) -> None:
    target.mkdir()
    for source in FIXTURES.iterdir():
        if source.is_file():
            shutil.copyfile(source, target / source.name)


def _raw_taint_json(executable: str, target: Path) -> dict[str, object]:
    # Mirror adapter process isolation and bounded output for temporary raw JSON
    # inspection. The parsed object is never printed or persisted.
    with tempfile.TemporaryDirectory(prefix="semgrep-taint-home-") as home_value:
        home = Path(home_value)
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        args = [
            executable, "scan", "--json", "--metrics=off", "--disable-version-check",
            "--oss-only", "--no-autofix", "--config", TAINT_RULE.name, "--", str(target),
        ]
        process = _run_process(args, TAINT_RULE.parent, env, SCAN_TIMEOUT_SECONDS)
    if process.exit_code != 0 or len(process.stdout) > MAX_OUTPUT_BYTES:
        pytest.fail("taint_semgrep_execution_failed")
    try:
        value = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pytest.fail("taint_semgrep_json_invalid")
    if not isinstance(value, dict):
        pytest.fail("taint_semgrep_json_invalid")
    return value


def _finding_locations(result) -> dict[tuple[str, str], tuple[int, str, str]]:
    return {
        (finding.file_path, finding.rule_id): (
            finding.line_number,
            finding.severity.value,
            finding.cwe or "",
        )
        for finding in result.findings
    }


def test_oss_taint_flows_baseline_difference_sanitizer_and_json_evidence(tmp_path: Path) -> None:
    executable = _require_semgrep()
    target = tmp_path / "synthetic-target"
    _copy_fixtures(target)

    adapter = SemgrepAdapter(TRUSTED_RULES)
    taint_output = adapter._scan_with_evidence(target, TAINT_RULE)
    taint = taint_output.result
    baseline = adapter.scan(target, BASELINE_RULE)
    assert taint.status is baseline.status is ScanStatus.COMPLETED
    assert taint.semgrep_version == baseline.semgrep_version == REQUIRED_VERSION
    assert taint.issues == baseline.issues == ()
    assert len(taint_output.taint_evidence) == len(taint.findings)
    findings_by_id = {finding.finding_id: finding for finding in taint.findings}
    assert all(item.finding_id in findings_by_id for item in taint_output.taint_evidence)
    assert all(item.flow_trace_status.value == "absent" for item in taint_output.taint_evidence)
    assert all(item.source_location is None and item.sink_location is None for item in taint_output.taint_evidence)
    assert all(item.source_location_status.value == "unknown" for item in taint_output.taint_evidence)
    assert all(item.sink_location_status.value == "unknown" for item in taint_output.taint_evidence)
    assert all(item.matched_file == findings_by_id[item.finding_id].file_path for item in taint_output.taint_evidence)
    assert all(item.matched_start.line == findings_by_id[item.finding_id].line_number for item in taint_output.taint_evidence)
    assert all(item.source_declaration_status.value == "available" for item in taint_output.taint_evidence)
    assert all(item.rules_file_sha256 for item in taint_output.taint_evidence)
    assert all(CANARY not in repr(item) for item in taint_output.taint_evidence)

    taint_plain = {
        path: (line, rule_id)
        for (path, rule_id), (line, _severity, _cwe) in _finding_locations(taint).items()
        if rule_id == "experimental.javascript-eval-taint"
    }
    taint_sanitized = {
        path: (line, rule_id)
        for (path, rule_id), (line, _severity, _cwe) in _finding_locations(taint).items()
        if rule_id == "experimental.javascript-eval-taint-with-synthetic-sanitizer"
    }
    assert taint_plain == {
        path: (line, "experimental.javascript-eval-taint")
        for path, line in EXPECTED_PLAIN_TAINT.items()
    }
    assert taint_sanitized == {
        path: (line, "experimental.javascript-eval-taint-with-synthetic-sanitizer")
        for path, line in EXPECTED_MODELED_SANITIZER.items()
    }
    expected_sanitizer_policy_negatives = set("DEGL")
    observed_sanitizer_policy_negatives = set("ABCDEFGHKL") - set(taint_sanitized)
    assert (len(set(taint_sanitized) & set(EXPECTED_MODELED_SANITIZER)),
            len(set(taint_sanitized) & expected_sanitizer_policy_negatives),
            len(set(EXPECTED_MODELED_SANITIZER) - set(taint_sanitized)),
            len(observed_sanitizer_policy_negatives & expected_sanitizer_policy_negatives)) == (6, 0, 0, 4)
    assert {
        path: (line, rule_id, severity, cwe)
        for (path, rule_id), (line, severity, cwe) in _finding_locations(baseline).items()
    } == {
        path: (line, "baseline.javascript-dynamic-eval", "high", "CWE-95")
        for path, line in EXPECTED_BASELINE.items()
    }

    for finding in (*taint.findings, *baseline.findings):
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-95"
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert CANARY not in finding.model_dump_json()
        assert CANARY not in repr(finding)

    raw = _raw_taint_json(executable, target)
    assert raw.get("version") == REQUIRED_VERSION
    assert raw.get("engine_requested") == "OSS"
    assert raw.get("errors") == []
    scanned = raw.get("paths", {}).get("scanned") if isinstance(raw.get("paths"), dict) else None
    assert isinstance(scanned, list) and len(scanned) == len(list(FIXTURES.iterdir()))
    raw_results = raw.get("results")
    assert isinstance(raw_results, list) and len(raw_results) == len(taint.findings)
    assert {item.get("extra", {}).get("engine_kind") for item in raw_results} == {"OSS"}
    # Semgrep 1.182.1 reported sink locations and match snippets, but no explicit
    # source location, metavariable map, or dataflow trace in this OSS JSON.
    for item in raw_results:
        extra = item.get("extra", {})
        assert "dataflow_trace" not in item
        assert "metavars" not in item
        assert "dataflow_trace" not in extra
        assert "metavars" not in extra
        assert isinstance(item.get("start"), dict)
        assert isinstance(item.get("end"), dict)

    # In-scope cases A-H, K, L have deterministic expected flow labels.
    # I/J depend on interprocedural/interfile analysis and are reported separately.
    in_scope = set("ABCDEFGHKL")
    expected_positive = set("ABCFGHK")
    observed_positive = {Path(path).stem[0] for path in taint_plain}
    tp = len(observed_positive & expected_positive)
    fp = len(observed_positive & (in_scope - expected_positive))
    fn = len(expected_positive - observed_positive)
    tn = len((in_scope - expected_positive) - observed_positive)
    assert (tp, fp, fn, tn) == (7, 0, 0, 3)
    assert {"I", "J"}.isdisjoint(observed_positive)
