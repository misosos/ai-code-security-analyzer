from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).parent / "benchmark" / "phase6e" / "evaluate.py"
SPEC = importlib.util.spec_from_file_location("phase6e_heldout_evaluate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def _finding(rule: str, path: str, line: int = 1, finding_id: str = "F-1", status="unverified") -> SimpleNamespace:
    return SimpleNamespace(rule_id=rule, file_path=path, line_number=line, finding_id=finding_id,
                           status=status, evidence="PHASE6E_SYNTHETIC_CANARY", description="return eval(secret)")


def _results(*findings, status="completed"):
    return {
        profile: SimpleNamespace(status=status, semgrep_version="1.182.1", exit_code=0, findings=())
        for profile in benchmark.PROFILES
    } | {"baseline": SimpleNamespace(status=status, semgrep_version="1.182.1", exit_code=0, findings=findings)}


def test_frozen_corpus_has_60_new_cases_and_separate_axes() -> None:
    dataset = benchmark.load_dataset()
    assert dataset.version == "phase6e-heldout-synthetic-v1"
    assert len(dataset.cases) == 60
    assert {case.security_review_relevance for case in dataset.cases} == {
        "review_worthy", "lower_priority", "undetermined",
    }
    assert {signal for case in dataset.cases for signal in case.expected_rule_signals.values()} == {
        "positive", "negative", "out_of_scope",
    }
    assert {case.security_coverage_gap for case in dataset.cases} == {
        "in_scope", "unsupported_pattern", "unsupported_flow", "unsupported_context",
        "insufficient_information",
    }


@pytest.mark.parametrize("mutation", ["version", "duplicate", "bad_label", "bad_gap", "bad_location", "confirmation"])
def test_invalid_mutated_oracle_is_rejected(tmp_path: Path, mutation: str) -> None:
    root = MODULE_PATH.parent
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    oracle = json.loads((root / "oracle.json").read_text(encoding="utf-8"))
    if mutation == "version":
        oracle["evaluation_set_version"] = "phase6e-other"
    elif mutation == "duplicate":
        oracle["cases"][1]["case_id"] = oracle["cases"][0]["case_id"]
    elif mutation == "bad_label":
        oracle["cases"][0]["expected_rule_signals"] = {"baseline.javascript-dynamic-eval": "confirmed"}
    elif mutation == "bad_gap":
        oracle["cases"][0]["security_coverage_gap"] = "safe"
    elif mutation == "bad_location":
        case = next(item for item in oracle["cases"] if item["expected_matches"] and any(item["expected_matches"].values()))
        rule = next(rule for rule, locations in case["expected_matches"].items() if locations)
        case["expected_matches"][rule] = [{"path": "../../outside.js", "line": 1}]
        case["expected_cardinality"][rule] = 1
    else:
        oracle["cases"][0]["vulnerability_confirmation"] = "confirmed"
    manifest_path, oracle_path = tmp_path / "manifest.json", tmp_path / "oracle.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
    with pytest.raises(benchmark.EvaluationInputError):
        benchmark.load_dataset(manifest_path, oracle_path)


def test_path_mapping_uses_unique_case_prefix_not_filename() -> None:
    dataset = benchmark.load_dataset()
    first = benchmark._case_for_path("js_eval/EJX01_invoice_preview/src/preview.js", dataset)
    assert first is not None and first[0].case_id == "EJX01_invoice_preview"
    assert first[1] == "src/preview.js"
    assert benchmark._case_for_path("other/EJX01_invoice_preview/src/preview.js", dataset) is None
    assert benchmark._case_for_path("../EJX01_invoice_preview/src/preview.js", dataset) is None


def test_case_and_finding_metrics_keep_oos_and_relevance_separate() -> None:
    dataset = benchmark.load_dataset()
    report = benchmark.evaluate_results(dataset, _results())
    assert report["metrics_available"] is True
    metrics = report["metrics_by_rule"]["baseline.javascript-dynamic-eval"]
    assert metrics["rule_signal_case_metrics"]["FN"] > 0
    assert metrics["rule_signal_case_metrics"]["TN"] > 0
    assert metrics["rule_signal_case_metrics"]["precision"] is None
    assert metrics["coverage_gap"]["review_worthy_case_count"] > 0
    assert metrics["coverage_gap"]["review_worthy_cases_by_gap"]["unsupported_pattern"] > 0
    assert report["confirmed_vulnerability"] == "NOT_EVALUATED"


def test_unmapped_finding_invalidates_all_metrics() -> None:
    report = benchmark.evaluate_results(benchmark.load_dataset(), _results(
        _finding("baseline.javascript-dynamic-eval", "somewhere_else/src/a.js", 1),
    ))
    assert report["metrics_available"] is False
    assert report["metrics_by_rule"] == {}
    assert report["unmapped_findings"] == [{"profile": "baseline", "rule_id": "baseline.javascript-dynamic-eval"}]


def test_partial_scan_cannot_be_scored() -> None:
    report = benchmark.evaluate_results(benchmark.load_dataset(), _results(status="partial"))
    assert report["metrics_available"] is False
    assert report["metrics_by_rule"] == {}


def test_unexpected_rule_id_or_confirmed_finding_invalidates_scores() -> None:
    unknown = benchmark.evaluate_results(benchmark.load_dataset(), _results(
        _finding("unexpected.rule", "js_eval/EJX01_invoice_preview/src/preview.js"),
    ))
    assert unknown["metrics_available"] is False
    assert unknown["unexpected_rule_ids"] == [{"profile": "baseline", "rule_id": "unexpected.rule"}]

    confirmed = benchmark.evaluate_results(benchmark.load_dataset(), _results(
        _finding("baseline.javascript-dynamic-eval", "js_eval/EJX01_invoice_preview/src/preview.js", 2, status="confirmed"),
    ))
    assert confirmed["metrics_available"] is False
    assert confirmed["scan_runs"]["baseline"]["all_findings_unverified"] is False


def test_output_omits_untrusted_finding_text_canary_and_absolute_path() -> None:
    import json
    report = benchmark.evaluate_results(benchmark.load_dataset(), _results(
        _finding("baseline.javascript-dynamic-eval", "js_eval/EJX01_invoice_preview/src/preview.js", 2),
    ))
    serialized = json.dumps(report)
    assert "PHASE6E_SYNTHETIC_CANARY" not in serialized
    assert "return eval(secret)" not in serialized
    assert str(benchmark.ROOT) not in serialized


def test_expected_rule_and_cross_category_observations_are_separate() -> None:
    report = benchmark.evaluate_results(benchmark.load_dataset(), _results(
        _finding("baseline.javascript-dynamic-eval", "eval_taint/ETX01_route_preview/src/routes/preview.js", 3),
    ))
    assert report["metrics_available"] is True
    assert report["cross_category_observations"] == [{
        "profile": "baseline", "rule_id": "baseline.javascript-dynamic-eval", "case_id": "ETX01_route_preview",
        "security_review_relevance": "review_worthy",
    }]
    dynamic = report["metrics_by_rule"]["baseline.javascript-dynamic-eval"]
    assert dynamic["coverage_gap"]["reported_finding_relevance"] == {
        "review_worthy": 0, "lower_priority": 0, "undetermined": 0,
    }
    assert dynamic["cross_category_reported_finding_relevance"]["review_worthy"] == 1
