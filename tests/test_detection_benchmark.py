from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).parent / "benchmark" / "evaluate.py"
SPEC = importlib.util.spec_from_file_location("phase6a_benchmark_evaluate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def _copy_inputs(tmp_path: Path) -> tuple[Path, Path]:
    manifest = json.loads((benchmark.BENCHMARK_ROOT / "manifest.json").read_text())
    oracle = json.loads((benchmark.BENCHMARK_ROOT / "oracle.json").read_text())
    manifest_path, oracle_path = tmp_path / "manifest.json", tmp_path / "oracle.json"
    manifest_path.write_text(json.dumps(manifest))
    oracle_path.write_text(json.dumps(oracle))
    return manifest_path, oracle_path


def _result(status: str = "completed", findings: tuple = ()) -> SimpleNamespace:
    return SimpleNamespace(status=status, semgrep_version="1.182.1", exit_code=0, issues=(), findings=findings)


def test_oracle_is_fixed_versioned_and_independent_dataset_has_50_cases() -> None:
    dataset = benchmark.load_dataset()
    assert dataset.version == "phase6a-synthetic-v1"
    assert len(dataset.cases) == 50
    assert len({case.case_id for case in dataset.cases}) == 50
    assert {case.category for case in dataset.cases} == {
        "js_eval", "react_html", "firestore", "eval_taint", "command_injection"
    }
    sanitizer_case = next(case for case in dataset.cases if case.case_id == "T05_modeled_sanitizer")
    assert sanitizer_case.expected_rule_signals["experimental.javascript-eval-taint"] == "positive"
    assert sanitizer_case.expected_rule_signals[
        "experimental.javascript-eval-taint-with-synthetic-sanitizer"
    ] == "negative"
    assert sanitizer_case.security_review_relevance == "lower_priority"


@pytest.mark.parametrize("mutation", ["missing_field", "duplicate_id", "bad_label", "bad_rule", "bad_line", "bad_version"])
def test_invalid_oracle_is_rejected(tmp_path: Path, mutation: str) -> None:
    manifest_path, oracle_path = _copy_inputs(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    oracle = json.loads(oracle_path.read_text())
    if mutation == "missing_field":
        del oracle["cases"][0]["rationale"]
    elif mutation == "duplicate_id":
        oracle["cases"][1]["case_id"] = oracle["cases"][0]["case_id"]
    elif mutation == "bad_label":
        oracle["cases"][0]["expected_rule_signals"][next(iter(oracle["cases"][0]["expected_rule_signals"]))] = "confirmed_vulnerability"
    elif mutation == "bad_rule":
        item = oracle["cases"][0]
        old = next(iter(item["expected_rule_signals"]))
        item["expected_rule_signals"]["arbitrary.rule"] = item["expected_rule_signals"].pop(old)
        item["expected_match_locations"]["arbitrary.rule"] = item["expected_match_locations"].pop(old)
        item["expected_cardinality"]["arbitrary.rule"] = item["expected_cardinality"].pop(old)
    elif mutation == "bad_line":
        item = next(item for item in oracle["cases"] if item["expected_match_locations"])
        rule_id = next(iter(item["expected_match_locations"]))
        item["expected_match_locations"][rule_id] = [999]
    else:
        oracle["evaluation_set_version"] = "phase6a-synthetic-v2"
    manifest_path.write_text(json.dumps(manifest))
    oracle_path.write_text(json.dumps(oracle))
    with pytest.raises(benchmark.BenchmarkInputError):
        benchmark.load_dataset(manifest_path, oracle_path)

    manifest_path, oracle_path = _copy_inputs(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"][0]["path"] = "cases/js_eval/no-such-case.js"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(benchmark.BenchmarkInputError):
        benchmark.load_dataset(manifest_path, oracle_path)


def test_duplicate_manifest_case_id_and_path_escape_are_rejected(tmp_path: Path) -> None:
    manifest_path, oracle_path = _copy_inputs(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"][1]["case_id"] = manifest["cases"][0]["case_id"]
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(benchmark.BenchmarkInputError):
        benchmark.load_dataset(manifest_path, oracle_path)

    manifest_path, oracle_path = _copy_inputs(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"][0]["path"] = "../../outside.js"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(benchmark.BenchmarkInputError):
        benchmark.load_dataset(manifest_path, oracle_path)


def test_binary_metrics_handle_zero_denominators_and_finding_duplicates() -> None:
    case = benchmark.Case(
        case_id="X01_negative", category="js_eval", language="javascript", path="cases/js_eval/X01.js",
        expected_rule_signals={"baseline.javascript-dynamic-eval": "negative"},
        expected_match_locations={"baseline.javascript-dynamic-eval": ()},
        expected_cardinality={"baseline.javascript-dynamic-eval": 0}, security_review_relevance="undetermined",
    )
    score = benchmark.score_rule("baseline.javascript-dynamic-eval", (case,), {})
    assert score["case_metrics"] == {
        "TP": 0, "FP": 0, "FN": 0, "TN": 1, "precision": None, "recall": None,
        "false_positive_rate": 0.0,
    }

    positives = benchmark.load_dataset()
    positive = next(c for c in positives.cases if c.case_id == "E01_route_expression")
    score = benchmark.score_rule(
        "baseline.javascript-dynamic-eval", (positive,), {positive.case_id: [3, 3]}
    )
    assert score["case_metrics"]["TP"] == 1
    assert score["finding_metrics"]["TP"] == 1
    assert score["finding_metrics"]["FP"] == 1
    assert score["duplicate_findings"] == 1
    assert score["location_discrepancies"] == []


def test_failed_scan_is_not_scored_and_partial_findings_do_not_become_fn() -> None:
    dataset = benchmark.load_dataset()
    report = benchmark.evaluate_with_results(
        dataset,
        {"baseline": _result("partial"), "eval_taint": _result(), "command_injection": _result()},
    )
    assert report["metrics_available"] is False
    assert report["metrics_by_rule"] == {}
    assert report["scan_runs"]["baseline"]["scan_status"] == "partial"


def test_unknown_rule_unmapped_finding_and_canary_are_not_disclosed() -> None:
    dataset = benchmark.load_dataset()
    finding = SimpleNamespace(
        file_path="not-in-manifest.js", rule_id="unknown.rule", line_number=9,
        description="SYNTHETIC_CANARY_PRIVATE_CODE",
    )
    report = benchmark.evaluate_with_results(
        dataset,
        {"baseline": _result(findings=(finding,)), "eval_taint": _result(), "command_injection": _result()},
    )
    serialized = json.dumps(report, sort_keys=True)
    assert "SYNTHETIC_CANARY_PRIVATE_CODE" not in serialized
    assert "not-in-manifest.js" not in serialized
    assert report["unexpected_findings"] == [
        {"profile": "baseline", "rule_id": "unknown.rule", "case_id": "unmapped"}
    ]
    assert "unknown.rule" in report["scan_runs"]["baseline"]["unexpected_rule_ids"]


def test_known_rule_match_outside_declared_case_scope_is_reported_unscored() -> None:
    dataset = benchmark.load_dataset()
    finding = SimpleNamespace(
        file_path="eval_taint/T01_query_direct.js",
        rule_id="baseline.javascript-dynamic-eval",
        line_number=2,
        description="not copied into benchmark output",
    )
    report = benchmark.evaluate_with_results(
        dataset,
        {"baseline": _result(findings=(finding,)), "eval_taint": _result(), "command_injection": _result()},
    )
    assert report["unscored_out_of_scope_findings"] == [
        {
            "profile": "baseline",
            "rule_id": "baseline.javascript-dynamic-eval",
            "case_id": "T01_query_direct",
            "line_number": 2,
        }
    ]
    assert report["metrics_by_rule"]["baseline.javascript-dynamic-eval"]["case_metrics"]["TP"] == 0


def test_expected_location_mismatch_is_reported_without_changing_oracle() -> None:
    dataset = benchmark.load_dataset()
    positive = next(c for c in dataset.cases if c.case_id == "E01_route_expression")
    score = benchmark.score_rule(
        "baseline.javascript-dynamic-eval", (positive,), {positive.case_id: [99]}
    )
    assert score["case_metrics"]["TP"] == 1
    assert score["location_discrepancies"] == [
        {"case_id": "E01_route_expression", "expected_lines": [3], "actual_lines": [99]}
    ]
