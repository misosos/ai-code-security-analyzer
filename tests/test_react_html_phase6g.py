"""Phase 6G React HTML Sink pilot, Semgrep OSS integration on synthetic code."""

from __future__ import annotations

import os
import shutil
from collections import Counter
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "react_html_phase6g"
RULES = ROOT / "rules"
BASELINE = RULES / "security-baseline.yml"
EXPERIMENTAL = RULES / "experimental" / "react-html-sink-coverage.yml"
EXPECTED_VERSION = "1.182.1"
EXPERIMENTAL_RULE_ID = "experimental.react-html-sink-coverage"
BASELINE_RULE_ID = "baseline.react-dangerous-html"
CANARY = "PHASE6G_SYNTHETIC_REACT_CANARY"
VULNERABILITY_CONFIRMATION = "NOT_EVALUATED"

# Labels and locations were fixed before running the experimental rule.
SIGNALS = {
    "P1_jsx_variable_props": "positive",
    "P2_jsx_aliased_react_import": "positive",
    "P3_tsx_variable_props": "positive",
    "P4_create_element_direct": "positive",
    "P5_create_element_alias_import": "positive",
    "P6_static_html_sink": "positive",
    "N1_other_library_create_element": "negative",
    "N2_fake_react_object": "negative",
    "N3_react_shadowed_parameter": "negative",
    "N4_similar_prop": "negative",
    "N5_plain_object_dunder_html": "negative",
    "N6_react_text_render": "negative",
    "N7_unused_html_string": "negative",
    "N8_direct_jsx_object_is_baseline_only": "negative",
    "N9_wrong_prop_value_type": "negative",
    "N10_variable_prop_wrong_shape": "negative",
    "O1_dom_inner_html": "out_of_scope",
    "O2_child_component_props": "out_of_scope",
    "O3_create_element_helper_props": "out_of_scope",
    "O4_named_create_element_import": "out_of_scope",
    "O5_jsx_member_expression_props": "out_of_scope",
}
RELEVANCE = {
    "P1_jsx_variable_props": "review_worthy",
    "P2_jsx_aliased_react_import": "review_worthy",
    "P3_tsx_variable_props": "review_worthy",
    "P4_create_element_direct": "review_worthy",
    "P5_create_element_alias_import": "review_worthy",
    "P6_static_html_sink": "lower_priority",
    "N1_other_library_create_element": "lower_priority",
    "N2_fake_react_object": "lower_priority",
    "N3_react_shadowed_parameter": "lower_priority",
    "N4_similar_prop": "lower_priority",
    "N5_plain_object_dunder_html": "lower_priority",
    "N6_react_text_render": "lower_priority",
    "N7_unused_html_string": "lower_priority",
    "N8_direct_jsx_object_is_baseline_only": "review_worthy",
    "N9_wrong_prop_value_type": "undetermined",
    "N10_variable_prop_wrong_shape": "lower_priority",
    "O1_dom_inner_html": "review_worthy",
    "O2_child_component_props": "undetermined",
    "O3_create_element_helper_props": "review_worthy",
    "O4_named_create_element_import": "review_worthy",
    "O5_jsx_member_expression_props": "review_worthy",
}
EXPECTED_EXPERIMENTAL_LINES = {
    "P1_jsx_variable_props": 5,
    "P2_jsx_aliased_react_import": 3,
    "P3_tsx_variable_props": 5,
    "P4_create_element_direct": 3,
    "P5_create_element_alias_import": 3,
    "P6_static_html_sink": 3,
}


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _synthetic_target(target: Path) -> None:
    target.mkdir()
    for fixture in FIXTURES.iterdir():
        if fixture.is_dir():
            shutil.copytree(fixture, target / fixture.name)


def test_phase6g_labels_are_complete_and_scoped() -> None:
    assert set(SIGNALS) == set(RELEVANCE)
    assert set(SIGNALS) == {path.name for path in FIXTURES.iterdir() if path.is_dir()}
    assert {case for case, signal in SIGNALS.items() if signal == "positive"} == set(EXPECTED_EXPERIMENTAL_LINES)
    assert set(SIGNALS.values()) == {"positive", "negative", "out_of_scope"}
    assert set(RELEVANCE.values()) <= {"review_worthy", "lower_priority", "undetermined"}
    assert VULNERABILITY_CONFIRMATION == "NOT_EVALUATED"


def test_phase6g_semgrep_rule_signal_and_relevance(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "synthetic-target"
    _synthetic_target(target)

    result = SemgrepAdapter(RULES)._scan_with_evidence(target, EXPERIMENTAL).result
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == EXPECTED_VERSION
    assert result.exit_code == 0
    assert result.issues == ()

    findings_by_case: dict[str, list] = {}
    for finding in result.findings:
        case = Path(finding.file_path).parts[0]
        findings_by_case.setdefault(case, []).append(finding)
        assert finding.rule_id == EXPERIMENTAL_RULE_ID
        assert finding.severity is Severity.MEDIUM
        assert finding.cwe == "CWE-79"
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert finding.line_number == EXPECTED_EXPERIMENTAL_LINES[case]
        assert CANARY not in finding.model_dump_json()

    observed = set(findings_by_case)
    positives = {case for case, signal in SIGNALS.items() if signal == "positive"}
    negatives = {case for case, signal in SIGNALS.items() if signal == "negative"}
    tp, fp = len(positives & observed), len(negatives & observed)
    fn, tn = len(positives - observed), len(negatives - observed)
    assert (tp, fp, fn, tn) == (6, 0, 0, 10), sorted(observed)
    assert all(len(findings_by_case.get(case, ())) == 1 for case in positives)
    assert all(not findings_by_case.get(case) for case in negatives)
    assert observed & {case for case, signal in SIGNALS.items() if signal == "out_of_scope"} == set()
    assert len(result.findings) == 6
    assert Counter(RELEVANCE[case] for case in observed) == Counter(
        {"review_worthy": 5, "lower_priority": 1}
    )

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    false_positive_rate = fp / (fp + tn) if fp + tn else None
    assert (precision, recall, false_positive_rate) == (1.0, 1.0, 0.0)


def test_existing_react_baseline_is_unchanged_and_non_overlapping(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "synthetic-target"
    _synthetic_target(target)
    adapter = SemgrepAdapter(RULES)

    baseline = adapter.scan(target, BASELINE)
    experimental = adapter.scan(target, EXPERIMENTAL)
    assert baseline.status is experimental.status is ScanStatus.COMPLETED
    assert baseline.semgrep_version == experimental.semgrep_version == EXPECTED_VERSION
    baseline_by_case = {Path(item.file_path).parts[0]: item for item in baseline.findings}
    experimental_by_case = {Path(item.file_path).parts[0]: item for item in experimental.findings}
    assert set(baseline_by_case) == {"N8_direct_jsx_object_is_baseline_only"}
    assert baseline_by_case["N8_direct_jsx_object_is_baseline_only"].rule_id == BASELINE_RULE_ID
    assert baseline_by_case["N8_direct_jsx_object_is_baseline_only"].line_number == 2
    assert set(experimental_by_case) == set(EXPECTED_EXPERIMENTAL_LINES)
    assert not (set(baseline_by_case) & set(experimental_by_case))


def test_phase6e_react_gap_cases_remain_outside_baseline(tmp_path: Path) -> None:
    _require_semgrep()
    phase6e = ROOT / "tests/benchmark/phase6e/cases/react_html"
    selected = ("RHX04_notice_content", "RHX09_dom_api", "RHX10_create_element")
    target = tmp_path / "phase6e-react-cases"
    target.mkdir()
    for case_id in selected:
        shutil.copytree(phase6e / case_id, target / case_id)
    result = SemgrepAdapter(RULES).scan(target, BASELINE)
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == EXPECTED_VERSION
    assert result.findings == ()
    assert result.issues == ()
