from __future__ import annotations

import json
import os
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests/fixtures/firestore_hardening"
CASES_ROOT = FIXTURE_ROOT / "cases"
BASELINE_RULES = ROOT / "rules/security-baseline.yml"
RULE_ID = "baseline.firestore-unconditional-write"
PHASE6A_MANIFEST_SHA256 = "954f9e33359bdcd478a6edbdcc83b9aa8cb962c01e7e90c5b6f60ef1b2c23c53"
PHASE6A_ORACLE_SHA256 = "d5c10325bb0ce38f9187739afb704287de1cdbab94e879d57ade152eb05e1747"
HARDENING_MANIFEST_SHA256 = "19cfb57a0ce60b0efad6b94609d07e19a37878d85f4e4480d98e0090b63170d8"
HARDENING_ORACLE_SHA256 = "37cfcd625d6d3e4029474f61809afc04e13a350e8254cd0572fca8dfd0eaba18"


def _load_oracle() -> dict:
    return json.loads((FIXTURE_ROOT / "oracle.json").read_text(encoding="utf-8"))


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _scan_hardening_fixtures():
    with TemporaryDirectory(prefix="firestore-hardening-") as temporary:
        target = Path(temporary) / "cases"
        shutil.copytree(CASES_ROOT, target)
        canary_path = target / "P01_write" / "firestore.rules"
        canary_path.write_text(
            canary_path.read_text(encoding="utf-8") + "// SYNTHETIC_FIRESTORE_CANARY\n",
            encoding="utf-8",
        )
        return SemgrepAdapter(ROOT / "rules").scan(target, BASELINE_RULES)


def _measure(result, oracle: dict) -> dict:
    actual: dict[str, list] = defaultdict(list)
    for finding in result.findings:
        if finding.rule_id == RULE_ID:
            actual[Path(finding.file_path).parent.name].append(finding)
    counts = Counter()
    duplicates = 0
    location_mismatches = []
    results = []
    for case in oracle["cases"]:
        case_id = case["case_id"]
        label = case["label"]
        findings = actual.get(case_id, [])
        expected_count = case["expected_cardinality"]
        expected_lines = case["expected_match_lines"]
        lines = [finding.line_number for finding in findings]
        if label == "positive":
            counts["TP" if findings else "FN"] += 1
        elif label == "negative":
            counts["FP" if findings else "TN"] += 1
        duplicates += max(0, len(findings) - expected_count) if expected_count else max(0, len(findings) - 1)
        if sorted(set(lines)) != sorted(expected_lines):
            location_mismatches.append({"case_id": case_id, "expected": expected_lines, "actual": lines})
        results.append({"case_id": case_id, "expected": label, "actual_count": len(findings)})
    tp, fp, fn, tn = (counts[x] for x in ("TP", "FP", "FN", "TN"))
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "duplicate_findings": duplicates,
        "location_mismatches": location_mismatches,
        "cases": results,
    }


def test_oracle_is_frozen_and_phase6a_dataset_is_unchanged() -> None:
    manifest_path = ROOT / "tests/benchmark/manifest.json"
    oracle_path = ROOT / "tests/benchmark/oracle.json"
    import hashlib

    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == PHASE6A_MANIFEST_SHA256
    assert hashlib.sha256(oracle_path.read_bytes()).hexdigest() == PHASE6A_ORACLE_SHA256
    assert hashlib.sha256((FIXTURE_ROOT / "manifest.json").read_bytes()).hexdigest() == HARDENING_MANIFEST_SHA256
    assert hashlib.sha256((FIXTURE_ROOT / "oracle.json").read_bytes()).hexdigest() == HARDENING_ORACLE_SHA256
    oracle = _load_oracle()
    assert oracle["dataset_version"] == "firestore-hardening-v1"
    assert oracle["case_count"] == 27
    assert sum(case["label"] == "positive" for case in oracle["cases"]) == 13
    assert sum(case["label"] == "negative" for case in oracle["cases"]) == 14
    assert all(case["expected_match_lines"] for case in oracle["cases"] if case["label"] == "positive")


@pytest.mark.parametrize(
    "case_id",
    [
        "P01_write", "P02_create", "P03_update", "P04_delete", "P05_create_update",
        "P06_create_update_delete", "P07_read_write", "P08_read_create", "P09_get_update",
        "P10_read_create_update_delete", "P11_delete_list_create", "P12_tabs_spacing",
        "P13_two_declarations",
    ],
)
def test_positive_fixture_has_its_predeclared_rule_signal(case_id: str) -> None:
    oracle = _load_oracle()
    case = next(item for item in oracle["cases"] if item["case_id"] == case_id)
    assert case["label"] == "positive"
    assert case["expected_match_lines"]


def test_rule_metadata_and_phase6a_benchmark_source_are_unchanged() -> None:
    content = BASELINE_RULES.read_text(encoding="utf-8")
    firestore_rule = content.split(f"id: {RULE_ID}", 1)[1]
    assert "severity: ERROR" in firestore_rule
    assert 'CWE-284: Improper Access Control' in firestore_rule
    assert '"**/firestore.rules"' in firestore_rule


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_firestore_hardening_semgrep_integration() -> None:
    _require_semgrep()
    oracle = _load_oracle()
    result = _scan_hardening_fixtures()
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == "1.182.1"
    assert result.exit_code == 0
    assert result.issues == ()
    measured = _measure(result, oracle)

    findings_by_case: dict[str, list] = defaultdict(list)
    for finding in result.findings:
        case_id = Path(finding.file_path).parent.name
        findings_by_case[case_id].append(finding)
        assert finding.rule_id == RULE_ID
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-284"
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert not Path(finding.file_path).is_absolute()
        assert finding.file_path == Path(finding.file_path).as_posix()

    # The new multi-operation target and all explicitly supported operations
    # must be detected. Metrics remain observations; no 100% accuracy gate.
    for case in oracle["cases"]:
        if case["label"] == "positive":
            assert len(findings_by_case[case["case_id"]]) == case["expected_cardinality"]
            assert sorted(f.line_number for f in findings_by_case[case["case_id"]]) == case["expected_match_lines"]
    assert findings_by_case["P06_create_update_delete"]

    strict_negative_ids = {
        case["case_id"] for case in oracle["cases"]
        if case["label"] == "negative" and not case["exploratory"]
    }
    assert not (strict_negative_ids & findings_by_case.keys())
    # N14 remains an exploratory negative in the frozen Phase 6B oracle. The
    # shared adapter now discards its regex candidate only after confirming the
    # exact match span lies in a closed block comment.
    assert measured["TP"] + measured["FN"] == 13
    assert measured["FP"] + measured["TN"] == 14
    assert measured["TP"] == 13 and measured["FP"] == 0 and measured["FN"] == 0 and measured["TN"] == 14
    assert measured["duplicate_findings"] == 0

    representative = findings_by_case["P06_create_update_delete"][0]
    assert representative.line_number == 4
    assert len({f.finding_id for f in findings_by_case["P13_two_declarations"]}) == 2

    serialized = json.dumps(measured, sort_keys=True)
    assert "SYNTHETIC_FIRESTORE_CANARY" not in serialized
    assert str(ROOT) not in serialized
    assert "allow create" not in serialized
