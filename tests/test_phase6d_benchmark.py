from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).parent / "benchmark" / "phase6d" / "evaluate.py"
SPEC = importlib.util.spec_from_file_location("phase6d_generalization_evaluate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def _results(status: str = "completed", findings: tuple = ()) -> dict[str, SimpleNamespace]:
    return {
        profile: SimpleNamespace(status=status, semgrep_version="1.182.1", exit_code=0, issues=(), findings=findings if profile == "baseline" else ())
        for profile in benchmark.PROFILES
    }


def test_frozen_dataset_has_50_independently_labelled_cases() -> None:
    dataset = benchmark.load_dataset()
    assert dataset.version == "phase6d-generalization-v1"
    assert len(dataset.cases) == 50
    assert Counter(case.category for case in dataset.cases) == Counter({
        "js_eval": 10, "react_html": 10, "firestore": 10, "eval_taint": 10, "command_injection": 10,
    })
    assert {signal for case in dataset.cases for signal in case.expected_rule_signals.values()} == {
        "positive", "negative", "out_of_scope",
    }
    assert all(case.limitations for case in dataset.cases)
    corrected = next(case for case in dataset.cases if case.case_id == "ET07_alternate_request_name")
    assert all(signal == "positive" for signal in corrected.expected_rule_signals.values())
    assert benchmark.ORIGINAL_ORACLE_SHA256 == "af911e6c2a02d23e4ce6dcee970931002360ec13c40600964dcdd724f88df2e3"
    assert benchmark.ORACLE_SHA256 == "0d70ef57a247e31bb8bbea1258069a649ae5ead764f2a423e938c7e05e0c4ea8"


@pytest.mark.parametrize("mutation", ["version", "duplicate", "unknown_rule", "bad_label", "bad_location", "bad_relevance"])
def test_invalid_phase6d_oracle_is_rejected(tmp_path: Path, mutation: str) -> None:
    data_root = MODULE_PATH.parent
    manifest = json.loads((data_root / "manifest.json").read_text(encoding="utf-8"))
    oracle = json.loads((data_root / "oracle.json").read_text(encoding="utf-8"))
    if mutation == "version":
        oracle["evaluation_set_version"] = "phase6d-generalization-v2"
    elif mutation == "duplicate":
        oracle["cases"][1]["case_id"] = oracle["cases"][0]["case_id"]
    elif mutation == "unknown_rule":
        item = next(case for case in oracle["cases"] if case["category"] == "js_eval")
        item["expected_rule_signals"]["arbitrary.rule"] = "positive"
        item["expected_matches"]["arbitrary.rule"] = [{"path": "src/example.js", "line": 1}]
        item["expected_cardinality"]["arbitrary.rule"] = 1
    elif mutation == "bad_label":
        oracle["cases"][0]["expected_rule_signals"] = {
            key: "confirmed_vulnerability" for key in oracle["cases"][0]["expected_rule_signals"]
        }
    elif mutation == "bad_location":
        item = next(case for case in oracle["cases"] if case["expected_matches"])
        rule = next(iter(item["expected_matches"]))
        item["expected_matches"][rule] = [{"path": "../../outside.js", "line": 1}]
    else:
        oracle["cases"][0]["security_review_relevance"] = "safe"
    manifest_path, oracle_path = tmp_path / "manifest.json", tmp_path / "oracle.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
    with pytest.raises(benchmark.EvaluationInputError):
        benchmark.load_dataset(manifest_path, oracle_path)


def test_fixture_content_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    manifest = json.loads((MODULE_PATH.parent / "manifest.json").read_text(encoding="utf-8"))
    manifest["cases"][0]["files"][0]["sha256"] = "0" * 64
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(benchmark.EvaluationInputError, match="benchmark_fixture_integrity_invalid"):
        benchmark.load_dataset(manifest_path, MODULE_PATH.parent / "oracle.json")


def test_scoring_separates_binary_signals_out_of_scope_and_review_relevance() -> None:
    positive = benchmark.Case(
        "EJ02_route_query", "js_eval", "javascript", "cases/js_eval/EJ02_route_query",
        {"baseline.javascript-dynamic-eval": "positive"},
        {"baseline.javascript-dynamic-eval": (("src/routes/search.js", 3),)},
        {"baseline.javascript-dynamic-eval": 1}, "review_worthy", "synthetic rationale", ("synthetic limitation",),
    )
    negative = benchmark.Case(
        "EJ05_comment_example", "js_eval", "javascript", "cases/js_eval/EJ05_comment_example",
        {"baseline.javascript-dynamic-eval": "negative"},
        {"baseline.javascript-dynamic-eval": ()}, {"baseline.javascript-dynamic-eval": 0},
        "undetermined", "synthetic rationale", ("synthetic limitation",),
    )
    out_scope = benchmark.Case(
        "EJ08_alias_wrapper", "js_eval", "javascript", "cases/js_eval/EJ08_alias_wrapper",
        {"baseline.javascript-dynamic-eval": "out_of_scope"},
        {"baseline.javascript-dynamic-eval": ()}, {"baseline.javascript-dynamic-eval": 0},
        "review_worthy", "synthetic rationale", ("synthetic limitation",),
    )
    result = benchmark.score_rule(
        "baseline.javascript-dynamic-eval", (positive, negative, out_scope),
        {positive.case_id: [("src/routes/search.js", 3)],
         negative.case_id: [("src/logging/audit.ts", 2)], out_scope.case_id: [("src/compat/evaluator.js", 3)]},
    )
    assert result["rule_signal_case_metrics"]["TP"] == 1
    assert result["rule_signal_case_metrics"]["FP"] == 1
    assert result["rule_signal_case_metrics"]["TN"] == 0
    assert result["out_of_scope_matches"] == [{"case_id": "EJ08_alias_wrapper", "match_count": 1}]
    assert result["reported_finding_relevance"] == {
        "lower_priority": 0, "review_worthy": 2, "undetermined": 1,
    }


def test_incomplete_scan_is_unscored_and_never_turns_missing_findings_into_fn() -> None:
    dataset = benchmark.load_dataset()
    report = benchmark.evaluate_results(dataset, _results(status="partial"))
    assert report["metrics_available"] is False
    assert report["metrics_by_rule"] == {}


def test_unmapped_finding_invalidates_metric_run() -> None:
    dataset = benchmark.load_dataset()
    finding = SimpleNamespace(
        file_path="outside/not-in-manifest.js", rule_id="baseline.javascript-dynamic-eval", line_number=2,
    )
    report = benchmark.evaluate_results(dataset, _results(findings=(finding,)))
    assert report["metrics_available"] is False
    assert report["metrics_by_rule"] == {}
    assert report["unmapped_findings"] == [{
        "profile": "baseline", "rule_id": "baseline.javascript-dynamic-eval",
    }]


def test_zero_denominators_duplicates_and_expected_location_mismatch_are_explicit() -> None:
    assert benchmark._metrics(Counter()) == {
        "TP": 0, "FP": 0, "FN": 0, "TN": 0,
        "precision": None, "recall": None, "false_positive_rate": None,
    }
    case = next(case for case in benchmark.load_dataset().cases if case.case_id == "EJ02_route_query")
    rule = "baseline.javascript-dynamic-eval"
    score = benchmark.score_rule(rule, (case,), {case.case_id: [("src/routes/search.js", 3), ("src/routes/search.js", 4)]})
    assert score["rule_signal_case_metrics"]["TP"] == 1
    assert score["finding_metrics"]["TP"] == 1
    assert score["finding_metrics"]["FP"] == 1
    assert score["duplicate_findings"] == 1
    assert score["location_mismatches"] == [{
        "case_id": case.case_id,
        "expected_matches": [("src/routes/search.js", 3)],
        "actual_matches": [("src/routes/search.js", 3), ("src/routes/search.js", 4)],
    }]


def test_wrong_semgrep_version_yields_no_scores() -> None:
    dataset = benchmark.load_dataset()
    results = _results()
    results["baseline"].semgrep_version = "1.0.0"
    report = benchmark.evaluate_results(dataset, results)
    assert report["metrics_available"] is False
    assert report["metrics_by_rule"] == {}


def test_report_does_not_copy_finding_text_or_unmapped_absolute_paths() -> None:
    dataset = benchmark.load_dataset()
    canary = "PHASE6D_SYNTHETIC_CODE_CANARY"
    finding = SimpleNamespace(
        file_path="/private/synthetic/project/secret.js", rule_id="baseline.javascript-dynamic-eval",
        line_number=4, description=canary,
    )
    report = benchmark.evaluate_results(dataset, _results(findings=(finding,)))
    serialized = json.dumps(report, sort_keys=True)
    assert canary not in serialized
    assert "/private/synthetic/project" not in serialized
    assert report["unmapped_findings"]
