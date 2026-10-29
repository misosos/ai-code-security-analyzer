"""Phase 6H source-context evaluation on synthetic code, without code execution."""

from __future__ import annotations

import os
import shutil
from collections import Counter
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.taint_evidence import EvidenceState, TraceStatus


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "eval_source_phase6h"
RULES = ROOT / "rules"
CURRENT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
CONTEXT_RULE = RULES / "experimental" / "javascript-eval-source-context.yml"
VERSION = "1.182.1"
CURRENT_IDS = {
    "experimental.javascript-eval-taint",
    "experimental.javascript-eval-taint-with-synthetic-sanitizer",
}
CONTEXT_RULE_ID = "experimental.javascript-eval-source-context"
VULNERABILITY_CONFIRMATION = "NOT_EVALUATED"

# These classifications were fixed before scanning the Phase 6H fixtures.
# N11/N12 are context hard negatives but positive for the existing purely
# syntactic source-to-sink Rule Signal.
RULE_SIGNAL = {
    **{f"P{i:02d}_{name}": "positive" for i, name in enumerate((
        "express_query_direct", "express_body_alias", "express_post_body",
        "express_renamed_request", "express_commonjs", "express_conditional",
        "express_local_alias", "express_router", "generic_record", "generic_job",
        "generic_config", "generic_input", "unregistered_preview_handler",
        "unknown_registration_callback",
    ), 1)},
    **{f"N{i:02d}_{name}": "negative" for i, name in enumerate((
        "express_source_no_sink", "express_constant_eval", "express_wrong_request_field",
        "source_and_sink_unrelated", "generic_source_no_sink", "separate_functions",
        "alternate_field_alias", "body_to_non_eval", "modeled_source_to_parser",
        "unused_source_static_eval",
    ), 1)},
    "N11_request_parameter_shadowing": "positive",
    "N12_fake_express_package": "positive",
    "O01_alternate_field_direct": "out_of_scope",
    "O02_unknown_helper_boundary": "out_of_scope",
    "O03_cross_file_helper": "out_of_scope",
    "O04_destructured_source": "out_of_scope",
    "O05_unknown_wrapper": "out_of_scope",
    "O06_express_router_helper": "out_of_scope",
    "P15_express_synthetic_sanitizer": "positive",
}
SOURCE_CONTEXT = {
    **{f"P{i:02d}_{name}": "framework_context_observed" for i, name in enumerate((
        "express_query_direct", "express_body_alias", "express_post_body",
        "express_renamed_request", "express_commonjs", "express_conditional",
        "express_local_alias", "express_router",
    ), 1)},
    **{f"P{i:02d}_{name}": "generic_object_context" for i, name in enumerate((
        "generic_record", "generic_job", "generic_config", "generic_input",
    ), 9)},
    "P13_unregistered_preview_handler": "insufficient_context",
    "P14_unknown_registration_callback": "insufficient_context",
    "P15_express_synthetic_sanitizer": "framework_context_observed",
    **{f"N{i:02d}_{name}": "framework_context_observed" for i, name in enumerate((
        "express_source_no_sink", "express_constant_eval", "express_wrong_request_field",
        "source_and_sink_unrelated",
    ), 1)},
    "N05_generic_source_no_sink": "generic_object_context",
    "N06_separate_functions": "insufficient_context",
    "N07_alternate_field_alias": "insufficient_context",
    "N08_body_to_non_eval": "insufficient_context",
    "N09_modeled_source_to_parser": "framework_context_observed",
    "N10_unused_source_static_eval": "framework_context_observed",
    "N11_request_parameter_shadowing": "insufficient_context",
    "N12_fake_express_package": "generic_object_context",
    "O01_alternate_field_direct": "out_of_scope",
    "O02_unknown_helper_boundary": "insufficient_context",
    "O03_cross_file_helper": "insufficient_context",
    "O04_destructured_source": "framework_context_observed",
    "O05_unknown_wrapper": "insufficient_context",
    "O06_express_router_helper": "framework_context_observed",
}
RELEVANCE = {
    **{f"P{i:02d}_{name}": "review_worthy" for i, name in enumerate((
        "express_query_direct", "express_body_alias", "express_post_body",
        "express_renamed_request", "express_commonjs", "express_conditional",
        "express_local_alias", "express_router",
    ), 1)},
    "P09_generic_record": "lower_priority",
    "P10_generic_job": "undetermined",
    "P11_generic_config": "lower_priority",
    "P12_generic_input": "undetermined",
    "P13_unregistered_preview_handler": "undetermined",
    "P14_unknown_registration_callback": "undetermined",
    "P15_express_synthetic_sanitizer": "undetermined",
    **{f"N{i:02d}_{name}": "lower_priority" for i, name in enumerate((
        "express_source_no_sink", "express_constant_eval", "express_wrong_request_field",
        "source_and_sink_unrelated", "generic_source_no_sink", "separate_functions",
        "alternate_field_alias", "body_to_non_eval", "modeled_source_to_parser",
        "unused_source_static_eval",
    ), 1)},
    "N11_request_parameter_shadowing": "undetermined",
    "N12_fake_express_package": "undetermined",
    "O01_alternate_field_direct": "review_worthy",
    "O02_unknown_helper_boundary": "undetermined",
    "O03_cross_file_helper": "undetermined",
    "O04_destructured_source": "review_worthy",
    "O05_unknown_wrapper": "undetermined",
    "O06_express_router_helper": "undetermined",
}

EXPECTED_CURRENT_LINES = {
    "P01_express_query_direct": 4,
    "P02_express_body_alias": 5,
    "P03_express_post_body": 3,
    "P04_express_renamed_request": 4,
    "P05_express_commonjs": 4,
    "P06_express_conditional": 5,
    "P07_express_local_alias": 5,
    "P08_express_router": 4,
    "P09_generic_record": 2,
    "P10_generic_job": 2,
    "P11_generic_config": 3,
    "P12_generic_input": 3,
    "P13_unregistered_preview_handler": 2,
    "P14_unknown_registration_callback": 2,
    "P15_express_synthetic_sanitizer": 4,
    "N11_request_parameter_shadowing": 4,
    "N12_fake_express_package": 4,
}
CONTEXT_POSITIVE = {
    "P01_express_query_direct", "P02_express_body_alias", "P03_express_post_body",
    "P04_express_renamed_request", "P06_express_conditional", "P07_express_local_alias",
    "P15_express_synthetic_sanitizer",
}
CONTEXT_NEGATIVE = {
    "N01_express_source_no_sink", "N02_express_constant_eval",
    "N03_express_wrong_request_field", "N04_source_and_sink_unrelated",
    "N09_modeled_source_to_parser", "N10_unused_source_static_eval",
    "N11_request_parameter_shadowing", "N12_fake_express_package",
}
CONTEXT_OOS = set(RULE_SIGNAL) - CONTEXT_POSITIVE - CONTEXT_NEGATIVE
EXPECTED_CONTEXT_LINES = {case: EXPECTED_CURRENT_LINES[case] for case in CONTEXT_POSITIVE}


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _copy_all_fixtures(target: Path) -> None:
    target.mkdir()
    for case in FIXTURES.iterdir():
        if case.is_dir():
            shutil.copytree(case, target / case.name)


def test_phase6h_labels_cover_new_synthetic_corpus() -> None:
    fixture_ids = {path.name for path in FIXTURES.iterdir() if path.is_dir()}
    assert fixture_ids == set(RULE_SIGNAL) == set(SOURCE_CONTEXT) == set(RELEVANCE)
    assert len(fixture_ids) == 33
    assert {value for value in RULE_SIGNAL.values()} == {"positive", "negative", "out_of_scope"}
    assert set(SOURCE_CONTEXT.values()) <= {
        "framework_context_observed", "generic_object_context",
        "insufficient_context", "out_of_scope",
    }
    assert set(RELEVANCE.values()) <= {"review_worthy", "lower_priority", "undetermined"}
    assert set(EXPECTED_CURRENT_LINES) <= fixture_ids
    assert all(RELEVANCE[case] in {"review_worthy", "lower_priority", "undetermined"} for case in fixture_ids)
    assert VULNERABILITY_CONFIRMATION == "NOT_EVALUATED"
    source_context_positive = {case for case, signal in RULE_SIGNAL.items() if signal == "positive"}
    assert Counter(SOURCE_CONTEXT[case] for case in source_context_positive) == Counter({
        "framework_context_observed": 9,
        "generic_object_context": 5,
        "insufficient_context": 3,
    })
    assert Counter(RELEVANCE[case] for case in source_context_positive) == Counter({
        "review_worthy": 8,
        "lower_priority": 2,
        "undetermined": 7,
    })


def test_current_eval_taint_reports_syntactic_sources_without_provenance(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "phase6h"
    _copy_all_fixtures(target)
    output = SemgrepAdapter(RULES)._scan_with_evidence(target, CURRENT_RULE)
    result = output.result
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == VERSION
    assert result.exit_code == 0
    assert result.issues == ()

    observed: dict[str, set[str]] = {}
    for finding in result.findings:
        case = Path(finding.file_path).parts[0]
        observed.setdefault(case, set()).add(finding.rule_id)
        assert finding.rule_id in CURRENT_IDS
        assert "PHASE6H_SYNTHETIC_SOURCE_CANARY" not in finding.model_dump_json()
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert finding.line_number == EXPECTED_CURRENT_LINES[case]
    positive = {case for case, signal in RULE_SIGNAL.items() if signal == "positive"}
    negative = {case for case, signal in RULE_SIGNAL.items() if signal == "negative"}
    assert set(observed) == positive
    for case, rule_ids in observed.items():
        expected = CURRENT_IDS - {
            "experimental.javascript-eval-taint-with-synthetic-sanitizer"
        } if case == "P15_express_synthetic_sanitizer" else CURRENT_IDS
        assert rule_ids == expected
    assert sum(len(rule_ids) for rule_ids in observed.values()) == 33
    assert not (set(observed) & negative)
    assert not (set(observed) & {case for case, signal in RULE_SIGNAL.items() if signal == "out_of_scope"})

    # Case-level signal metrics for the primary rule (sanitizer model is reported separately).
    tp = len(positive & set(observed))
    fp = len(negative & set(observed))
    fn = len(positive - set(observed))
    tn = len(negative - set(observed))
    assert (tp, fp, fn, tn) == (17, 0, 0, 10)
    sanitizer_suppressed = "P15_express_synthetic_sanitizer"
    sanitizer_positive = positive - {sanitizer_suppressed}
    sanitizer_negative = negative | {sanitizer_suppressed}
    sanitizer_observed = {
        Path(finding.file_path).parts[0]
        for finding in result.findings
        if finding.rule_id == "experimental.javascript-eval-taint-with-synthetic-sanitizer"
    }
    assert sanitizer_observed == sanitizer_positive
    assert (
        len(sanitizer_positive & sanitizer_observed),
        len(sanitizer_negative & sanitizer_observed),
        len(sanitizer_positive - sanitizer_observed),
        len(sanitizer_negative - sanitizer_observed),
    ) == (16, 0, 0, 11)

    primary_evidence = [item for item in output.taint_evidence if item.rule_id == "experimental.javascript-eval-taint"]
    assert len(primary_evidence) == 17
    for item in primary_evidence:
        assert item.source_patterns_declared == ("$REQ.query.code", "$REQ.body.code")
        assert item.source_location is None
        assert item.source_location_status is EvidenceState.UNKNOWN
        assert item.sink_location is None
        assert item.sink_location_status is EvidenceState.UNKNOWN
        assert item.flow_trace_status is TraceStatus.ABSENT


def test_context_experiment_requires_observed_express_route_shape(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "phase6h-context"
    _copy_all_fixtures(target)
    output = SemgrepAdapter(RULES)._scan_with_evidence(target, CONTEXT_RULE)
    result = output.result
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == VERSION
    assert result.exit_code == 0
    assert result.issues == ()

    by_case: dict[str, int] = {}
    for finding in result.findings:
        case = Path(finding.file_path).parts[0]
        by_case[case] = by_case.get(case, 0) + 1
        assert finding.rule_id == CONTEXT_RULE_ID
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert finding.line_number == EXPECTED_CONTEXT_LINES[case]
    assert set(by_case) == CONTEXT_POSITIVE
    assert output.taint_evidence == ()  # this experimental ID is not in the trusted Evidence registry
    assert all(count == 1 for count in by_case.values())
    assert not (set(by_case) & CONTEXT_NEGATIVE)
    assert not (set(by_case) & CONTEXT_OOS)
    tp = len(CONTEXT_POSITIVE & set(by_case))
    fp = len(CONTEXT_NEGATIVE & set(by_case))
    fn = len(CONTEXT_POSITIVE - set(by_case))
    tn = len(CONTEXT_NEGATIVE - set(by_case))
    assert (tp, fp, fn, tn) == (7, 0, 0, 8)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    false_positive_rate = fp / (fp + tn) if fp + tn else None
    assert (precision, recall, false_positive_rate) == (1.0, 1.0, 0.0)


def test_phase6e_examples_keep_their_historical_labels_and_observed_matches(tmp_path: Path) -> None:
    _require_semgrep()
    source = ROOT / "tests/benchmark/phase6e/cases/eval_taint"
    ids = (
        "ETX01_route_preview", "ETX03_generic_record", "ETX07_alternate_field",
        "ETX08_helper_boundary", "ETX09_other_object", "ETX10_cross_file",
    )
    target = tmp_path / "phase6e-selected"
    target.mkdir()
    for case_id in ids:
        shutil.copytree(source / case_id, target / case_id)
    result = SemgrepAdapter(RULES).scan(target, CURRENT_RULE)
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == VERSION
    observed = {Path(item.file_path).parts[0] for item in result.findings}
    assert observed == {"ETX01_route_preview", "ETX03_generic_record", "ETX09_other_object"}
    assert len(result.findings) == 6
    context_result = SemgrepAdapter(RULES).scan(target, CONTEXT_RULE)
    assert context_result.status is ScanStatus.COMPLETED
    assert context_result.semgrep_version == VERSION
    assert context_result.findings == ()
