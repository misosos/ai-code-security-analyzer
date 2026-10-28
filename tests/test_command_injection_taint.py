"""Semgrep OSS 1.182.1 command-injection taint evaluation on synthetic code only."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.evidence_consumer import consume_evidence_summary
from ai_code_security_analyzer.evidence_sufficiency import ClaimType
from ai_code_security_analyzer.evidence_summary import FindingKind, build_evidence_summary
from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "command_injection"
TRUSTED_RULES = ROOT / "rules"
RULE = TRUSTED_RULES / "experimental" / "javascript-command-injection-taint.yml"
EXPECTED_VERSION = "1.182.1"
RULE_ID = "experimental.javascript-command-injection-taint"
CANARY = "SYNTHETIC_COMMAND_INJECTION_CANARY_ONLY"
EXPECTED_MATCH_LINES = {
    "P1_query_direct.js": 3,
    "P2_body_direct.js": 3,
    "P3_assignment.js": 4,
    "P4_multistep.js": 5,
    "P5_execsync.js": 3,
    "P6_branch.js": 7,
    "P7_node_import.js": 3,
    "P8_inline_require.ts": 2,
    "P9_commonjs_name_import.ts": 3,
    "E5_template_command.js": 3,
    "E6_destructured_require.js": 3,
    "E9_alias_require.js": 3,
}

# Ground truth is fixed before running Semgrep. These labels describe only the
# experiment's modeled source-to-first-command-argument relation.
POSITIVE_CASES = frozenset(
    {
        "P1_query_direct.js",
        "P2_body_direct.js",
        "P3_assignment.js",
        "P4_multistep.js",
        "P5_execsync.js",
        "P6_branch.js",
        "P7_node_import.js",
        "P8_inline_require.ts",
        "P9_commonjs_name_import.ts",
    }
)
NEGATIVE_CASES = frozenset(
    {
        "N1_constant.js",
        "N2_unrelated.js",
        "N3_input_but_constant.js",
        "N4_regexp_exec.js",
        "N5_mock_exec.js",
        "N6_other_argument.js",
        "N7_no_sink.js",
        "N8_string_only.js",
        "N9_fake_module_name.js",
    }
)
EXPLORATORY_CASES = frozenset(
    {
        "E1_interprocedural.js",
        "E2_interfile_source.js",
        "E2_interfile_sink.js",
        "E3_alias.js",
        "E4_dynamic_property.js",
        "E5_template_command.js",
        "E6_destructured_require.js",
        "E7_named_import.ts",
        "E8_alias_import.js",
        "E9_alias_require.js",
    }
)


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _synthetic_target(target: Path) -> None:
    target.mkdir()
    for fixture in FIXTURES.iterdir():
        if fixture.is_file():
            shutil.copyfile(fixture, target / fixture.name)


def test_command_injection_taint_against_frozen_synthetic_labels(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "synthetic-target"
    _synthetic_target(target)

    # The adapter enforces --oss-only, local trusted configuration, bounded
    # execution/output, no metrics/version check, and no autofix.
    output = SemgrepAdapter(TRUSTED_RULES)._scan_with_evidence(target, RULE)
    result = output.result
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == EXPECTED_VERSION
    assert result.exit_code == 0
    assert result.issues == ()

    findings_by_case: dict[str, list] = {}
    for finding in result.findings:
        findings_by_case.setdefault(Path(finding.file_path).name, []).append(finding)
        assert finding.rule_id == RULE_ID
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-78"
        assert finding.line_number == EXPECTED_MATCH_LINES[Path(finding.file_path).name]
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert finding.file_path == Path(finding.file_path).as_posix()
        assert not Path(finding.file_path).is_absolute()
        assert CANARY not in finding.model_dump_json()
        assert CANARY not in repr(finding)

    observed_cases = set(findings_by_case)
    expected_in_scope = POSITIVE_CASES | NEGATIVE_CASES
    observed_in_scope = observed_cases & expected_in_scope
    tp = len(POSITIVE_CASES & observed_in_scope)
    fp = len(NEGATIVE_CASES & observed_cases)
    fn = len(POSITIVE_CASES - observed_cases)
    tn = len(NEGATIVE_CASES - observed_cases)
    assert (tp, fp, fn, tn) == (9, 0, 0, 9), sorted(observed_cases)

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    false_positive_rate = fp / (fp + tn) if fp + tn else None
    assert (precision, recall, false_positive_rate) == (1.0, 1.0, 0.0)

    # One result per in-scope positive sink; no duplicate reports.
    assert all(len(findings_by_case.get(case, ())) == 1 for case in POSITIVE_CASES)
    assert all(not findings_by_case.get(case) for case in NEGATIVE_CASES)

    # Exploratory observations are deliberately excluded from TP/FP/FN/TN.
    exploratory_hits = observed_cases & EXPLORATORY_CASES
    assert exploratory_hits == {
        "E5_template_command.js",
        "E6_destructured_require.js",
        "E9_alias_require.js",
    }
    assert len(result.findings) == 12
    assert output.taint_evidence == ()  # New rule is not in the existing trusted evidence allowlist.

    representative = findings_by_case["P1_query_direct.js"][0]
    summary = build_evidence_summary(representative, scan_result=result)
    consumed = consume_evidence_summary(summary, representative, scan_result=result)
    assert consumed.finding_kind is FindingKind.PATTERN
    assert consumed.supports(ClaimType.MATCH_REPORTED)
    assert not consumed.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
    review = render_review(result, output.taint_evidence, rules_file=RULE, trusted_rules_directory=TRUSTED_RULES)
    assert "탐지 유형: 일반 패턴" in review
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in review


def test_fixture_labels_cover_documented_case_set() -> None:
    fixture_names = {path.name for path in FIXTURES.iterdir() if path.is_file()}
    assert POSITIVE_CASES.isdisjoint(NEGATIVE_CASES)
    assert POSITIVE_CASES.isdisjoint(EXPLORATORY_CASES)
    assert NEGATIVE_CASES.isdisjoint(EXPLORATORY_CASES)
    assert fixture_names == POSITIVE_CASES | NEGATIVE_CASES | EXPLORATORY_CASES


def test_no_shell_command_is_executed_by_fixture_evaluation() -> None:
    # Fixtures contain only static API calls; this assertion protects the
    # evaluation contract against accidentally adding an execution harness.
    assert not any(path.suffix not in {".js", ".ts"} for path in FIXTURES.iterdir())
