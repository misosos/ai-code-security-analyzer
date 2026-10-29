"""Phase 6F semantic command-execution scope on synthetic JavaScript only."""

from __future__ import annotations

import os
import shutil
from collections import Counter
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.evidence_consumer import consume_evidence_summary
from ai_code_security_analyzer.evidence_sufficiency import ClaimType
from ai_code_security_analyzer.evidence_summary import FindingKind, build_evidence_summary
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.taint_evidence import TraceStatus


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "command_injection_phase6f"
PHASE6E_PINNED_RULES = ROOT / "tests" / "benchmark" / "phase6e" / "pinned_rules"
PRE_CHANGE_RULE = PHASE6E_PINNED_RULES / "javascript-command-injection-taint.yml"
RULES = ROOT / "rules"
RULE = RULES / "experimental" / "javascript-command-injection-taint.yml"
RULE_ID = "experimental.javascript-command-injection-taint"
EXPECTED_VERSION = "1.182.1"
CANARY = "PHASE6F_SYNTHETIC_CANARY"

# Frozen before evaluating the Phase 6F fixtures. Signal labels describe only
# the configured taint rule, while relevance is a separate limited judgment.
SIGNALS = {
    "P1_spawn_named_shell_true": "positive",
    "P2_spawn_module_alias_shell_true": "positive",
    "P3_spawn_named_alias_command_shell_true": "positive",
    "P4_exec_module_alias_concat": "positive",
    "P5_req_shaped_local_object": "positive",
    "N1_spawn_default_shell": "negative",
    "N2_spawn_explicit_shell_false": "negative",
    "N3_spawn_shell_option_unknown": "negative",
    "N4_spawn_shell_true_source_in_env_only": "negative",
    "N5_fake_object_spawn": "negative",
    "N6_other_module_spawn": "negative",
    "N7_named_spawn_shadowed": "negative",
    "N8_other_request_property": "negative",
    "N9_static_shell_command": "negative",
    "X1_helper_boundary": "out_of_scope",
    "X2_missing_helper_definition": "out_of_scope",
    "O1_other_request_property": "out_of_scope",
}
RELEVANCE = {
    "P1_spawn_named_shell_true": "review_worthy",
    "P2_spawn_module_alias_shell_true": "review_worthy",
    "P3_spawn_named_alias_command_shell_true": "review_worthy",
    "P4_exec_module_alias_concat": "review_worthy",
    "P5_req_shaped_local_object": "undetermined",
    "N1_spawn_default_shell": "undetermined",
    "N2_spawn_explicit_shell_false": "undetermined",
    "N3_spawn_shell_option_unknown": "undetermined",
    "N4_spawn_shell_true_source_in_env_only": "lower_priority",
    "N5_fake_object_spawn": "lower_priority",
    "N6_other_module_spawn": "lower_priority",
    "N7_named_spawn_shadowed": "lower_priority",
    "N8_other_request_property": "undetermined",
    "N9_static_shell_command": "lower_priority",
    "X1_helper_boundary": "review_worthy",
    "X2_missing_helper_definition": "undetermined",
    "O1_other_request_property": "review_worthy",
}
EXPECTED_LINES = {
    "P1_spawn_named_shell_true": 6,
    "P2_spawn_module_alias_shell_true": 4,
    "P3_spawn_named_alias_command_shell_true": 3,
    "P4_exec_module_alias_concat": 3,
    "P5_req_shaped_local_object": 4,
}


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def test_phase6f_labels_are_complete_and_disjoint() -> None:
    assert set(SIGNALS) == set(RELEVANCE)
    assert set(SIGNALS) == {path.name for path in FIXTURES.iterdir() if path.is_dir()}
    assert set(SIGNALS.values()) <= {"positive", "negative", "out_of_scope"}
    assert set(RELEVANCE.values()) <= {"review_worthy", "lower_priority", "undetermined"}
    assert {case for case, signal in SIGNALS.items() if signal == "positive"} == set(EXPECTED_LINES)


def test_pinned_pre_change_rule_baseline_for_phase6f_cases(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "synthetic-target"
    target.mkdir()
    for fixture in FIXTURES.iterdir():
        if fixture.is_dir():
            shutil.copytree(fixture, target / fixture.name)

    result = SemgrepAdapter(PHASE6E_PINNED_RULES).scan(target, PRE_CHANGE_RULE)
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == EXPECTED_VERSION
    observed = [Path(finding.file_path).parts[0] for finding in result.findings]
    assert Counter(observed) == Counter(
        {"P4_exec_module_alias_concat": 1, "P5_req_shaped_local_object": 1}
    )
    assert len(result.findings) == 2
    assert result.issues == ()


def test_semgrep_phase6f_shell_semantics_and_false_positive_resistance(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "synthetic-target"
    target.mkdir()
    for fixture in FIXTURES.iterdir():
        if fixture.is_dir():
            shutil.copytree(fixture, target / fixture.name)

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, RULE)
    result = output.result
    assert result.status is ScanStatus.COMPLETED
    assert result.semgrep_version == EXPECTED_VERSION
    assert result.exit_code == 0
    assert result.issues == ()

    findings_by_case: dict[str, list] = {}
    for finding in result.findings:
        case = Path(finding.file_path).parts[0]
        findings_by_case.setdefault(case, []).append(finding)
        assert finding.rule_id == RULE_ID
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-78"
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert finding.line_number == EXPECTED_LINES[case]
        assert CANARY not in finding.model_dump_json()

    observed = set(findings_by_case)
    positives = {case for case, label in SIGNALS.items() if label == "positive"}
    negatives = {case for case, label in SIGNALS.items() if label == "negative"}
    tp = len(positives & observed)
    fp = len(negatives & observed)
    fn = len(positives - observed)
    tn = len(negatives - observed)
    assert (tp, fp, fn, tn) == (5, 0, 0, 9), sorted(observed)
    assert all(len(findings_by_case.get(case, ())) == 1 for case in positives)
    assert all(not findings_by_case.get(case) for case in negatives)
    assert observed & {case for case, label in SIGNALS.items() if label == "out_of_scope"} == set()
    assert len(result.findings) == 5
    assert Counter(RELEVANCE[case] for case in observed) == Counter(
        {"review_worthy": 4, "undetermined": 1}
    )
    unreported_review_worthy = {
        case
        for case, label in SIGNALS.items()
        if label == "out_of_scope" and RELEVANCE[case] == "review_worthy" and case not in observed
    }
    assert unreported_review_worthy == {"X1_helper_boundary", "O1_other_request_property"}

    evidence_by_id = {item.finding_id: item for item in output.taint_evidence}
    assert len(evidence_by_id) == len(output.taint_evidence) == len(result.findings)
    for finding in result.findings:
        evidence = evidence_by_id[finding.finding_id]
        assert evidence.association_status.value == "exact"
        assert evidence.rule_id == finding.rule_id
        assert evidence.matched_file == finding.file_path
        assert evidence.matched_start is not None
        assert evidence.matched_start.line == finding.line_number
        assert evidence.source_location is None
        assert evidence.sink_location is None
        assert evidence.flow_trace_status is TraceStatus.ABSENT

    # The new rule bytes and normalized declarations remain inside the existing
    # trust boundary. No source/sink location or trace is inferred from match.
    first = findings_by_case["P1_spawn_named_shell_true"][0]
    evidence = evidence_by_id[first.finding_id]
    summary = build_evidence_summary(
        first,
        evidence=evidence,
        scan_result=result,
        rules_file=RULE,
        trusted_rules_directory=RULES,
    )
    consumed = consume_evidence_summary(
        summary,
        first,
        evidence=evidence,
        scan_result=result,
        rules_file=RULE,
        trusted_rules_directory=RULES,
    )
    assert consumed.finding_kind is FindingKind.TAINT
    assert set(consumed.allowed_claim_types) == {
        ClaimType.MATCH_REPORTED,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        ClaimType.SOURCE_PATTERN_DECLARED,
        ClaimType.SINK_PATTERN_DECLARED,
        ClaimType.MATCH_LOCATION_OBSERVED,
    }
    assert first.status is FindingStatus.UNVERIFIED
