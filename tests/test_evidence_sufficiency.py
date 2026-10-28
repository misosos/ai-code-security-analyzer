"""Deterministic evidence claim policy; fixtures contain synthetic data only."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ai_code_security_analyzer.evidence_sufficiency import (
    ClaimDecision,
    ClaimType,
    EvidenceReason,
    EvidenceSource,
    evaluate_all_claims,
    evaluate_claim,
)
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import (
    AssociationStatus,
    EvidencePosition,
    EvidenceState,
    TraceStatus,
    TaintEvidence,
    build_taint_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULES = RULES / "experimental" / "javascript-eval-taint.yml"
TAINT_RULE_ID = "experimental.javascript-eval-taint"
SANITIZER_RULE_ID = "experimental.javascript-eval-taint-with-synthetic-sanitizer"
CANARY = "SYNTHETIC_PRIVATE_CODE_CANARY"


def _raw_result(rule_id: str = TAINT_RULE_ID) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "path": "src/sample.ts",
        "start": {"line": 8, "col": 3},
        "end": {"line": 8, "col": 14},
        "extra": {
            "message": CANARY,
            "severity": "ERROR",
            "metadata": {"cwe": "CWE-95"},
            "engine_kind": "OSS",
            "lines": CANARY,
        },
    }


def _fixture(tmp_path: Path, *, rule_id: str = TAINT_RULE_ID, status: ScanStatus = ScanStatus.COMPLETED):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    document = {
        "version": "1.182.1",
        "engine_requested": "OSS",
        "results": [_raw_result(rule_id)],
        "errors": [],
    }
    parsed = _parse_semgrep_json_internal(json.dumps(document).encode(), target)
    finding = parsed.parsed.findings[0]
    evidence = build_taint_evidence(
        parsed.document,
        parsed.result_findings,
        target,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )[0]
    scan = ScanResult(status=status, findings=(finding,), exit_code=0, semgrep_version="1.182.1")
    return finding, evidence, scan


def test_supported_claims_are_narrow_and_provenance_is_explicit(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    results = {
        item.claim_type: item
        for item in evaluate_all_claims(
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=TAINT_RULES,
            trusted_rules_directory=RULES,
        )
    }

    supported = {
        ClaimType.MATCH_REPORTED,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        ClaimType.SOURCE_PATTERN_DECLARED,
        ClaimType.SINK_PATTERN_DECLARED,
        ClaimType.MATCH_LOCATION_OBSERVED,
    }
    assert {claim for claim, item in results.items() if item.decision is ClaimDecision.SUPPORTED} == supported
    assert EvidenceSource.SEMGREP_OBSERVATION in results[ClaimType.TAINT_RULE_MATCH_REPORTED].evidence_provenance
    assert EvidenceSource.TRUSTED_RULE_DECLARATION in results[ClaimType.TAINT_RULE_MATCH_REPORTED].evidence_provenance
    assert EvidenceSource.ANALYZER_DERIVED in results[ClaimType.TAINT_RULE_MATCH_REPORTED].evidence_provenance
    assert results[ClaimType.TAINT_RULE_MATCH_REPORTED].reason_codes == ()
    assert all(CANARY not in item.model_dump_json() for item in results.values())
    assert all(finding.status is FindingStatus.UNVERIFIED for finding in scan.findings)
    assert all(finding.confirmation is None for finding in scan.findings)


def test_plain_pattern_finding_is_not_mislabeled_as_taint(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    finding = Finding(
        finding_id="pattern-only-id",
        rule_id="baseline.javascript-dynamic-eval",
        title="synthetic pattern",
        description="synthetic pattern result",
        severity=Severity.HIGH,
        source_tool="semgrep",
        file_path="src/sample.ts",
        line_number=8,
        evidence="Rule matched at line 8.",
    )
    scan = ScanResult(status=ScanStatus.COMPLETED, findings=(finding,), exit_code=0, semgrep_version="1.182.1")

    observed = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=scan)
    taint = evaluate_claim(finding, ClaimType.TAINT_RULE_MATCH_REPORTED, scan_result=scan)
    assert observed.decision is ClaimDecision.SUPPORTED
    assert taint.decision is ClaimDecision.UNAVAILABLE
    assert taint.reason_codes == (EvidenceReason.TAINT_EVIDENCE_UNAVAILABLE,)


@pytest.mark.parametrize(
    ("claim", "expected_reason"),
    [
        (ClaimType.SOURCE_LOCATION_IDENTIFIED, EvidenceReason.SOURCE_LOCATION_UNKNOWN),
        (ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED, EvidenceReason.SINK_ARGUMENT_LOCATION_UNKNOWN),
        (ClaimType.FLOW_TRACE_AVAILABLE, EvidenceReason.FLOW_TRACE_ABSENT),
    ],
)
def test_unobserved_source_sink_and_trace_are_unavailable(
    tmp_path: Path, claim: ClaimType, expected_reason: EvidenceReason
) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    result = evaluate_claim(finding, claim, evidence=evidence, scan_result=scan)
    assert result.decision is ClaimDecision.UNAVAILABLE
    assert expected_reason in result.reason_codes


@pytest.mark.parametrize(
    ("claim", "position_field", "status_field", "observed_field", "reason"),
    [
        (
            ClaimType.SOURCE_LOCATION_IDENTIFIED,
            "source_location",
            "source_location_status",
            "source_location",
            EvidenceReason.SOURCE_LOCATION_EVIDENCE_UNAVAILABLE,
        ),
        (
            ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED,
            "sink_location",
            "sink_location_status",
            "sink_location",
            EvidenceReason.SINK_ARGUMENT_LOCATION_EVIDENCE_UNAVAILABLE,
        ),
    ],
)
def test_location_claim_requires_a_structured_observation_marker(
    tmp_path: Path,
    claim: ClaimType,
    position_field: str,
    status_field: str,
    observed_field: str,
    reason: EvidenceReason,
) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    observed_position = replace(
        evidence,
        **{
            position_field: EvidencePosition(2, 4),
            status_field: EvidenceState.AVAILABLE,
        },
    )
    no_marker = evaluate_claim(finding, claim, evidence=observed_position, scan_result=scan)
    with_marker = evaluate_claim(
        finding,
        claim,
        evidence=replace(
            observed_position,
            observed_json_fields=(*observed_position.observed_json_fields, observed_field),
        ),
        scan_result=scan,
    )
    assert no_marker.decision is ClaimDecision.UNAVAILABLE
    assert reason in no_marker.reason_codes
    assert with_marker.decision is ClaimDecision.SUPPORTED


@pytest.mark.parametrize(
    ("trace_status", "expected_reason"),
    [
        (TraceStatus.EMPTY, EvidenceReason.FLOW_TRACE_EMPTY),
        (TraceStatus.MALFORMED, EvidenceReason.FLOW_TRACE_MALFORMED),
        (TraceStatus.UNSUPPORTED, EvidenceReason.FLOW_TRACE_UNSUPPORTED),
        (TraceStatus.NOT_EVALUATED, EvidenceReason.FLOW_TRACE_DETAILS_UNAVAILABLE),
        # A status flag alone is insufficient: the contract stores no trace steps.
        (TraceStatus.AVAILABLE, EvidenceReason.FLOW_TRACE_DETAILS_UNAVAILABLE),
    ],
)
def test_trace_states_never_claim_available_without_trace_payload(
    tmp_path: Path, trace_status: TraceStatus, expected_reason: EvidenceReason
) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    result = evaluate_claim(
        finding,
        ClaimType.FLOW_TRACE_AVAILABLE,
        evidence=replace(evidence, flow_trace_status=trace_status),
        scan_result=scan,
    )
    assert result.decision is ClaimDecision.UNAVAILABLE
    assert expected_reason in result.reason_codes


def test_rule_declaration_hash_and_patterns_are_revalidated(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    valid = evaluate_claim(
        finding,
        ClaimType.SOURCE_PATTERN_DECLARED,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    changed_hash = evaluate_claim(
        finding,
        ClaimType.SOURCE_PATTERN_DECLARED,
        evidence=replace(evidence, rules_file_sha256="0" * 64),
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    changed_pattern = evaluate_claim(
        finding,
        ClaimType.SOURCE_PATTERN_DECLARED,
        evidence=replace(evidence, source_patterns_declared=("$UNTRUSTED",)),
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )

    assert valid.decision is ClaimDecision.SUPPORTED
    assert changed_hash.decision is ClaimDecision.UNAVAILABLE
    assert EvidenceReason.RULE_HASH_MISMATCH in changed_hash.reason_codes
    assert changed_pattern.decision is ClaimDecision.UNAVAILABLE
    assert EvidenceReason.RULE_DECLARATION_MISMATCH in changed_pattern.reason_codes


@pytest.mark.parametrize(
    ("changes", "expected_decision", "expected_reason"),
    [
        ({"finding_id": "other-finding"}, ClaimDecision.AMBIGUOUS, EvidenceReason.FINDING_ID_MISMATCH),
        ({"rule_id": "other.rule"}, ClaimDecision.AMBIGUOUS, EvidenceReason.RULE_ID_MISMATCH),
        ({"matched_file": "../outside.ts"}, ClaimDecision.AMBIGUOUS, EvidenceReason.FILE_PATH_MISMATCH),
        (
            {"association_status": AssociationStatus.AMBIGUOUS},
            ClaimDecision.AMBIGUOUS,
            EvidenceReason.FINDING_ASSOCIATION_AMBIGUOUS,
        ),
        ({"matched_start": EvidencePosition(9, 3)}, ClaimDecision.AMBIGUOUS, EvidenceReason.MATCH_LOCATION_MALFORMED),
        (
            {"matched_end": EvidencePosition(7, 1)},
            ClaimDecision.INSUFFICIENT_EVIDENCE,
            EvidenceReason.MATCH_LOCATION_MALFORMED,
        ),
        ({"matched_end": EvidencePosition(8, 15)}, ClaimDecision.AMBIGUOUS, EvidenceReason.FINDING_ID_MISMATCH),
    ],
)
def test_finding_evidence_mismatches_fail_closed(
    tmp_path: Path,
    changes: dict[str, object],
    expected_decision: ClaimDecision,
    expected_reason: EvidenceReason,
) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    result = evaluate_claim(
        finding,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        evidence=replace(evidence, **changes),
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    assert result.decision is expected_decision
    assert expected_reason in result.reason_codes


def test_malformed_taint_evidence_shape_is_unavailable(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    malformed = replace(evidence, observed_json_fields=["raw free text"])  # type: ignore[arg-type]
    result = evaluate_claim(
        finding,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        evidence=malformed,
        scan_result=scan,
    )
    assert result.decision is ClaimDecision.UNAVAILABLE
    assert result.reason_codes == (EvidenceReason.TAINT_EVIDENCE_MALFORMED,)
    assert "raw free text" not in result.model_dump_json()


def test_duplicate_scan_finding_identity_is_ambiguous(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    duplicate_scan = replace(scan, findings=(finding, finding))
    result = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=duplicate_scan)
    taint_result = evaluate_claim(
        finding,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        evidence=evidence,
        scan_result=duplicate_scan,
    )
    assert result.decision is ClaimDecision.AMBIGUOUS
    assert taint_result.decision is ClaimDecision.AMBIGUOUS
    assert EvidenceReason.FINDING_ASSOCIATION_AMBIGUOUS in taint_result.reason_codes


@pytest.mark.parametrize("status", [
    ScanStatus.EXECUTION_FAILED,
    ScanStatus.NOT_INSTALLED,
    ScanStatus.INVALID_JSON,
    ScanStatus.TIMED_OUT,
    ScanStatus.OUTPUT_LIMIT_EXCEEDED,
])
def test_failed_scans_cannot_support_observed_match_claim(tmp_path: Path, status: ScanStatus) -> None:
    finding, evidence, scan = _fixture(tmp_path, status=status)
    match = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=scan)
    taint = evaluate_claim(finding, ClaimType.TAINT_RULE_MATCH_REPORTED, evidence=evidence, scan_result=scan)
    assert match.decision is ClaimDecision.UNAVAILABLE
    assert EvidenceReason.SCAN_FAILED in match.reason_codes
    assert taint.decision is ClaimDecision.UNAVAILABLE


def test_partial_scan_supports_only_individual_observations(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path, status=ScanStatus.PARTIAL)
    match = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=scan)
    taint = evaluate_claim(
        finding,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    assert match.decision is ClaimDecision.SUPPORTED
    assert match.reason_codes == (EvidenceReason.SCAN_PARTIAL,)
    assert taint.decision is ClaimDecision.INSUFFICIENT_EVIDENCE
    assert EvidenceReason.SCAN_NOT_COMPLETE in taint.reason_codes


def test_missing_scan_state_is_not_assumed_complete(tmp_path: Path) -> None:
    finding, evidence, _scan = _fixture(tmp_path)
    result = evaluate_claim(finding, ClaimType.MATCH_REPORTED)
    taint = evaluate_claim(finding, ClaimType.TAINT_RULE_MATCH_REPORTED, evidence=evidence)
    assert result.decision is ClaimDecision.UNAVAILABLE
    assert result.reason_codes == (EvidenceReason.SCAN_STATE_UNAVAILABLE,)
    assert taint.decision is ClaimDecision.UNAVAILABLE


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"exit_code": 1}, EvidenceReason.SCAN_RESULT_INCONSISTENT),
        ({"issues": ("synthetic issue",)}, EvidenceReason.SCAN_RESULT_INCONSISTENT),
        ({"semgrep_version": None}, EvidenceReason.ENGINE_UNVERIFIED),
    ],
)
def test_inconsistent_completed_scan_metadata_is_rejected(
    tmp_path: Path, changes: dict[str, object], reason: EvidenceReason
) -> None:
    finding, _evidence, scan = _fixture(tmp_path)
    result = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=replace(scan, **changes))
    assert result.decision is ClaimDecision.UNAVAILABLE
    assert reason in result.reason_codes


def test_non_tuple_scan_findings_are_not_treated_as_observations(tmp_path: Path) -> None:
    finding, _evidence, scan = _fixture(tmp_path)
    malformed_scan = replace(scan, findings=[finding])  # type: ignore[arg-type]
    result = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=malformed_scan)
    assert result.decision is ClaimDecision.UNAVAILABLE
    assert result.reason_codes == (EvidenceReason.SCAN_RESULT_INCONSISTENT,)


def test_sanitizer_declaration_is_not_a_match_or_effectiveness_proof(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path, rule_id=SANITIZER_RULE_ID)
    declaration = evaluate_claim(
        finding,
        ClaimType.SOURCE_PATTERN_DECLARED,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    sanitizer = evaluate_claim(finding, ClaimType.SANITIZER_MATCH_OBSERVED, evidence=evidence, scan_result=scan)
    effectiveness = evaluate_claim(finding, ClaimType.SANITIZER_EFFECTIVENESS_VERIFIED)
    assert declaration.decision is ClaimDecision.SUPPORTED
    assert sanitizer.decision is ClaimDecision.UNAVAILABLE
    assert sanitizer.reason_codes == (EvidenceReason.SANITIZER_MATCH_UNKNOWN,)
    assert effectiveness.decision is ClaimDecision.UNSUPPORTED_CLAIM
    assert effectiveness.reason_codes == (EvidenceReason.SANITIZER_EFFECTIVENESS_NOT_VERIFIED,)

    observed_marker = evaluate_claim(
        finding,
        ClaimType.SANITIZER_MATCH_OBSERVED,
        evidence=replace(
            evidence,
            sanitizer_match_status=EvidenceState.AVAILABLE,
            observed_json_fields=(*evidence.observed_json_fields, "sanitizer_match"),
        ),
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    assert observed_marker.decision is ClaimDecision.SUPPORTED
    assert EvidenceReason.RULE_FILE_SCAN_TIME_UNPROVEN in observed_marker.limitations


def test_confirmation_claim_is_never_created_from_static_evidence(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    result = evaluate_claim(
        finding,
        ClaimType.VULNERABILITY_CONFIRMED,
        evidence=evidence,
        scan_result=scan,
    )
    assert result.decision is ClaimDecision.UNSUPPORTED_CLAIM
    assert result.reason_codes == (EvidenceReason.INDEPENDENT_CONFIRMATION_REQUIRED,)
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.confirmation is None


def test_no_raw_code_or_canary_is_retained_in_gate_results(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    results = evaluate_all_claims(
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULES,
        trusted_rules_directory=RULES,
    )
    assert CANARY not in repr(evidence)
    assert all(CANARY not in item.model_dump_json() for item in results)
    assert all(item.finding_id == finding.finding_id for item in results)


def test_claim_evaluation_contract_rejects_open_vocab_and_extra_fields(tmp_path: Path) -> None:
    finding, _evidence, scan = _fixture(tmp_path)
    result = evaluate_claim(finding, ClaimType.MATCH_REPORTED, scan_result=scan)
    with pytest.raises(ValueError, match="unsupported_claim_type"):
        evaluate_claim(finding, "free_form_claim")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        type(result).model_validate({**result.model_dump(), "reason_codes": ("model supplied explanation",)})
    with pytest.raises(ValueError):
        type(result).model_validate({**result.model_dump(), "raw_message": CANARY})
