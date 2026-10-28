"""Expanded command-injection coverage and hard-negative evaluation."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from ai_code_security_analyzer.evidence_consumer import consume_evidence_summary
from ai_code_security_analyzer.evidence_sufficiency import ClaimType
from ai_code_security_analyzer.evidence_summary import FindingKind, build_evidence_summary
from ai_code_security_analyzer.markdown_report import render_markdown_review
from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "command_injection_hardening"
TRUSTED_RULES = ROOT / "rules"
RULE = TRUSTED_RULES / "experimental" / "javascript-command-injection-taint.yml"
EXPECTED_VERSION = "1.182.1"
RULE_ID = "experimental.javascript-command-injection-taint"
CANARY = "SYNTHETIC_PHASE4A2_CANARY_ONLY"

# Labels are frozen before observing the final rule output. Positive/negative
# labels refer only to this rule's stated request-source/command-argument goal.
POSITIVE_CASES = frozenset(f"P{number}_{suffix}" for number, suffix in [
    (10, "named_import.ts"),
    (11, "named_import_alias.ts"),
    (12, "destructured_require.js"),
    (13, "destructured_require_alias.js"),
    (14, "execsync_named_import.ts"),
    (15, "execsync_destructured_require.js"),
    (16, "module_alias_variable.js"),
    (17, "template_command.js"),
    (18, "command_reassignment.js"),
])
NEGATIVE_CASES = frozenset(f"N{number}_{suffix}" for number, suffix in [
    (10, "plain_object_exec.js"),
    (11, "regexp_exec.js"),
    (12, "mock_same_name.js"),
    (13, "fake_child_process.js"),
    (14, "child_process_shadowing.js"),
    (15, "exec_import_shadowing.ts"),
    (16, "other_package_exec.ts"),
    (17, "local_exec.js"),
    (18, "second_option_only.js"),
    (19, "callback_only.js"),
    (20, "unrelated_variable.js"),
    (21, "execsync_constant.js"),
    (22, "string_processing.js"),
    (23, "similar_module.js"),
    (24, "real_and_fake_exec.js"),
    (25, "reassigned_module.js"),
    (26, "distinct_request_objects.js"),
    (27, "taint_disconnected.js"),
    (28, "request_shape_only.js"),
])
EXPLORATORY_CASES = frozenset(f"X{number}_{suffix}" for number, suffix in [
    (1, "interprocedural.js"),
    (2, "interfile_source.js"),
    (2, "interfile_sink.js"),
    (3, "method_alias.js"),
    (4, "computed_property.js"),
    (5, "dynamic_require.js"),
    (6, "mutated_reference.js"),
    (7, "helper_return.js"),
    (8, "complex_template.js"),
    (9, "conditional_branch.js"),
    (10, "multiple_sinks.js"),
])
EXPECTED_MATCH_LINES = {
    "P10_named_import.ts": 3,
    "P11_named_import_alias.ts": 3,
    "P12_destructured_require.js": 3,
    "P13_destructured_require_alias.js": 3,
    "P14_execsync_named_import.ts": 3,
    "P15_execsync_destructured_require.js": 3,
    "P16_module_alias_variable.js": 4,
    "P17_template_command.js": 3,
    "P18_command_reassignment.js": 5,
    "X8_complex_template.js": 4,
    "X9_conditional_branch.js": 5,
    "X10_multiple_sinks.js": 3,
}


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _copy_fixtures(target: Path) -> None:
    target.mkdir()
    for fixture in FIXTURES.iterdir():
        if fixture.is_file():
            shutil.copyfile(fixture, target / fixture.name)


def test_expanded_import_forms_and_hard_negatives(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "synthetic-target"
    _copy_fixtures(target)
    adapter = SemgrepAdapter(TRUSTED_RULES)
    output = adapter._scan_with_evidence(target, RULE)
    result = output.result
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == EXPECTED_VERSION
    assert result.exit_code == 0
    assert result.issues == ()

    findings_by_case: dict[str, list] = {}
    for finding in result.findings:
        case = Path(finding.file_path).name
        findings_by_case.setdefault(case, []).append(finding)
        assert finding.rule_id == RULE_ID
        assert finding.line_number == EXPECTED_MATCH_LINES[case]
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-78"
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert not Path(finding.file_path).is_absolute()
        assert CANARY not in finding.model_dump_json()
        assert CANARY not in repr(finding)

    observed = set(findings_by_case)
    tp = len(POSITIVE_CASES & observed)
    fp = len(NEGATIVE_CASES & observed)
    fn = len(POSITIVE_CASES - observed)
    tn = len(NEGATIVE_CASES - observed)
    assert (tp, fp, fn, tn) == (9, 0, 0, 19)

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    false_positive_rate = fp / (fp + tn) if fp + tn else None
    assert (precision, recall, false_positive_rate) == (1.0, 1.0, 0.0)
    assert all(len(findings_by_case.get(case, ())) == 1 for case in POSITIVE_CASES)
    assert all(not findings_by_case.get(case) for case in NEGATIVE_CASES)
    assert observed & EXPLORATORY_CASES == {
        "X8_complex_template.js",
        "X9_conditional_branch.js",
        "X10_multiple_sinks.js",
    }
    assert len(findings_by_case["X10_multiple_sinks.js"]) == 1
    assert len(result.findings) == 12
    assert output.taint_evidence == ()

    # A second run checks stable Finding identity/location for this fixture set.
    repeated = adapter.scan(target, RULE)
    first_signature = tuple((f.finding_id, f.rule_id, f.file_path, f.line_number) for f in result.findings)
    second_signature = tuple((f.finding_id, f.rule_id, f.file_path, f.line_number) for f in repeated.findings)
    assert repeated.status is ScanStatus.COMPLETED
    assert repeated.semgrep_version == EXPECTED_VERSION
    assert second_signature == first_signature

    representative = findings_by_case["P10_named_import.ts"][0]
    summary = build_evidence_summary(representative, scan_result=result)
    consumed = consume_evidence_summary(summary, representative, scan_result=result)
    assert consumed.finding_kind is FindingKind.PATTERN
    assert consumed.supports(ClaimType.MATCH_REPORTED)
    assert not consumed.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
    review = render_review(result, output.taint_evidence, rules_file=RULE, trusted_rules_directory=TRUSTED_RULES)
    markdown = render_markdown_review(
        result,
        output.taint_evidence,
        rules_file=RULE,
        trusted_rules_directory=TRUSTED_RULES,
    )
    assert "탐지 유형: 일반 패턴" in review
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in review
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in markdown
    assert CANARY not in review and CANARY not in markdown


def test_hardening_fixture_labels_are_complete_and_disjoint() -> None:
    fixture_names = {path.name for path in FIXTURES.iterdir() if path.is_file()}
    assert POSITIVE_CASES.isdisjoint(NEGATIVE_CASES)
    assert POSITIVE_CASES.isdisjoint(EXPLORATORY_CASES)
    assert NEGATIVE_CASES.isdisjoint(EXPLORATORY_CASES)
    assert fixture_names == POSITIVE_CASES | NEGATIVE_CASES | EXPLORATORY_CASES
