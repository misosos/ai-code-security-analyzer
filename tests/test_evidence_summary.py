"""EvidenceSummary consistency tests use synthetic Semgrep JSON only."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_code_security_analyzer.evidence_summary import (
    MAX_EVIDENCE_SUMMARY_BYTES,
    EvidenceSummary,
    EvidenceSummaryError,
    FindingKind,
    RuleDeclarationStatus,
    build_evidence_summary,
    validate_evidence_summary,
)
from ai_code_security_analyzer.evidence_sufficiency import (
    ClaimDecision,
    ClaimType,
    EvidenceReason,
    EvidenceSource,
    evaluate_all_claims,
)
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import build_taint_evidence


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
TAINT_RULE_ID = "experimental.javascript-eval-taint"
CANARY = "SYNTHETIC_SUMMARY_CANARY_VALUE"


def _fixture(tmp_path: Path, *, taint: bool = True, status: ScanStatus = ScanStatus.COMPLETED):
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    rule_id = TAINT_RULE_ID if taint else "baseline.javascript-dynamic-eval"
    document = {
        "version": "1.182.1",
        "engine_requested": "OSS",
        "results": [
            {
                "check_id": rule_id,
                "path": "src/synthetic.ts",
                "start": {"line": 4, "col": 2},
                "end": {"line": 4, "col": 8},
                "extra": {
                    "message": CANARY,
                    "severity": "ERROR",
                    "engine_kind": "OSS",
                    "lines": CANARY,
                },
            }
        ],
        "errors": [],
    }
    parsed = _parse_semgrep_json_internal(json.dumps(document).encode(), target)
    finding = parsed.parsed.findings[0]
    evidence = (
        build_taint_evidence(
            parsed.document,
            parsed.result_findings,
            target,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )[0]
        if taint
        else None
    )
    scan = ScanResult(status, (finding,), (), 0, "1.182.1")
    return finding, evidence, scan


def _build(tmp_path: Path, *, taint: bool = True, status: ScanStatus = ScanStatus.COMPLETED):
    finding, evidence, scan = _fixture(tmp_path, taint=taint, status=status)
    return finding, evidence, scan, build_evidence_summary(
        finding,
        scan_result=scan,
        evidence=evidence,
        rules_file=TAINT_RULE if taint else None,
        trusted_rules_directory=RULES if taint else None,
    )


def test_taint_summary_preserves_every_gate_decision_and_provenance(tmp_path: Path) -> None:
    finding, evidence, scan, summary = _build(tmp_path)
    gate = evaluate_all_claims(
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    by_type = {item.claim_type: item for item in (*summary.supported_claims, *summary.restricted_claims)}
    assert len(by_type) == len(ClaimType)
    assert len(summary.supported_claims) + len(summary.restricted_claims) == len(ClaimType)
    assert all(by_type[item.claim_type].to_gate_evaluation() == item for item in gate)
    assert summary.finding_kind is FindingKind.TAINT
    assert summary.trusted_rule_declaration_status is RuleDeclarationStatus.VERIFIED
    assert summary.scan_status is ScanStatus.COMPLETED
    assert summary.match_observation_status is ClaimDecision.SUPPORTED
    assert summary.finding_verification_status is FindingStatus.UNVERIFIED
    assert ClaimType.SOURCE_LOCATION_IDENTIFIED not in {item.claim_type for item in summary.supported_claims}
    assert EvidenceReason.FLOW_TRACE_ABSENT in next(
        item.reason_codes for item in summary.restricted_claims if item.claim_type is ClaimType.FLOW_TRACE_AVAILABLE
    )
    assert EvidenceSource.TRUSTED_RULE_DECLARATION in summary.evidence_provenance


def test_pattern_summary_does_not_infer_taint(tmp_path: Path) -> None:
    finding, evidence, scan, summary = _build(tmp_path, taint=False)
    assert evidence is None
    assert summary.finding_kind is FindingKind.PATTERN
    assert summary.association_status.value == "not_applicable"
    assert summary.trusted_rule_declaration_status is RuleDeclarationStatus.NOT_APPLICABLE
    assert ClaimType.MATCH_REPORTED in {item.claim_type for item in summary.supported_claims}
    taint = next(item for item in summary.restricted_claims if item.claim_type is ClaimType.TAINT_RULE_MATCH_REPORTED)
    assert taint.decision is ClaimDecision.UNAVAILABLE
    assert EvidenceReason.TAINT_EVIDENCE_UNAVAILABLE in taint.reason_codes
    assert validate_evidence_summary(summary, finding, scan_result=scan) == summary


def test_partial_and_failed_scan_status_are_preserved(tmp_path: Path) -> None:
    _, _, _, partial = _build(tmp_path, status=ScanStatus.PARTIAL)
    assert partial.scan_status is ScanStatus.PARTIAL
    assert partial.match_observation_status is ClaimDecision.SUPPORTED
    assert EvidenceReason.SCAN_PARTIAL in next(
        item.reason_codes for item in partial.supported_claims if item.claim_type is ClaimType.MATCH_REPORTED
    )
    finding, evidence, scan = _fixture(tmp_path / "failed", status=ScanStatus.TIMED_OUT)
    failed_scan = replace(scan, findings=(), exit_code=None)
    failed = build_evidence_summary(finding, evidence=evidence, scan_result=failed_scan)
    assert failed.scan_status is ScanStatus.TIMED_OUT
    assert failed.match_observation_status is ClaimDecision.UNAVAILABLE
    assert ClaimType.MATCH_REPORTED in {item.claim_type for item in failed.restricted_claims}


def test_gate_mismatch_or_incomplete_summary_is_rejected(tmp_path: Path) -> None:
    finding, evidence, scan, summary = _build(tmp_path)
    with pytest.raises(EvidenceSummaryError):
        validate_evidence_summary(
            summary.model_copy(update={"supported_claims": summary.supported_claims[:-1]}),
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )
    with pytest.raises(EvidenceSummaryError):
        validate_evidence_summary(
            summary.model_copy(update={"finding_id": "semgrep:" + "f" * 24}),
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )


def test_rule_hash_mismatch_is_retained_without_taint_classification(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    changed = replace(evidence, rules_file_sha256="0" * 64)
    summary = build_evidence_summary(
        finding,
        evidence=changed,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert summary.finding_kind is FindingKind.UNCLASSIFIED
    assert summary.association_status.value == "exact"
    assert summary.trusted_rule_declaration_status is RuleDeclarationStatus.UNVERIFIED
    taint = next(item for item in summary.restricted_claims if item.claim_type is ClaimType.TAINT_RULE_MATCH_REPORTED)
    assert EvidenceReason.RULE_HASH_MISMATCH in taint.reason_codes


def test_duplicate_finding_association_is_preserved_as_ambiguous(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    duplicate = replace(scan, findings=(finding, finding))
    summary = build_evidence_summary(finding, evidence=evidence, scan_result=duplicate)
    assert summary.association_status.value == "ambiguous"
    assert summary.match_observation_status is ClaimDecision.AMBIGUOUS
    assert summary.finding_kind is FindingKind.UNCLASSIFIED


def test_evidence_for_another_finding_is_not_mixed_into_summary(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    other = finding.model_copy(update={"finding_id": "semgrep:" + "a" * 24})
    summary = build_evidence_summary(other, evidence=evidence, scan_result=scan)
    assert summary.finding_id == other.finding_id
    assert summary.finding_kind is FindingKind.UNCLASSIFIED
    assert summary.association_status.value == "ambiguous"
    assert all(item.finding_id in {None, other.finding_id} for item in summary.restricted_claims)


@pytest.mark.parametrize("mutation", ["decision", "reason", "provenance", "duplicate", "other_finding"])
def test_modified_claims_are_rejected_against_recomputed_gate(tmp_path: Path, mutation: str) -> None:
    finding, evidence, scan, summary = _build(tmp_path)
    supported = list(summary.supported_claims)
    restricted = list(summary.restricted_claims)
    if mutation == "decision":
        supported[0] = supported[0].model_copy(update={"decision": ClaimDecision.UNAVAILABLE})
    elif mutation == "reason":
        restricted[0] = restricted[0].model_copy(update={"reason_codes": ()})
    elif mutation == "provenance":
        supported[0] = supported[0].model_copy(update={"evidence_provenance": ()})
    elif mutation == "duplicate":
        supported.append(supported[0])
    elif mutation == "other_finding":
        supported[0] = supported[0].model_copy(update={"finding_id": "semgrep:" + "0" * 24})
    altered = summary.model_copy(update={"supported_claims": tuple(supported), "restricted_claims": tuple(restricted)})
    with pytest.raises(EvidenceSummaryError):
        validate_evidence_summary(
            altered,
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )


def test_summary_model_rejects_open_fields_and_open_codes() -> None:
    with pytest.raises(ValidationError):
        EvidenceSummary.model_validate({"claim": "free text"})
    with pytest.raises(ValidationError):
        EvidenceSummary.model_validate({"finding_id": "not-opaque", "rule_id": "baseline.rule"})


def test_complete_summary_model_rejects_unknown_fields_and_codes(tmp_path: Path) -> None:
    _finding, _evidence, _scan, summary = _build(tmp_path)
    with pytest.raises(ValidationError):
        EvidenceSummary.model_validate({**summary.model_dump(), "raw_message": CANARY})
    restricted = summary.restricted_claims[0]
    with pytest.raises(ValidationError):
        type(restricted).model_validate({**restricted.model_dump(), "reason_codes": (CANARY,)})


def test_summary_excludes_raw_messages_paths_and_canary(tmp_path: Path) -> None:
    _finding, _evidence, _scan, summary = _build(tmp_path)
    encoded = summary.model_dump_json().encode()
    assert CANARY.encode() not in encoded
    assert b"src/synthetic.ts" not in encoded
    assert b"message" not in encoded
    assert b"lines" not in encoded
    assert len(encoded) <= MAX_EVIDENCE_SUMMARY_BYTES


def test_summary_is_deterministic_and_has_a_hard_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    kwargs = {"evidence": evidence, "scan_result": scan, "rules_file": TAINT_RULE, "trusted_rules_directory": RULES}
    first = build_evidence_summary(finding, **kwargs)
    second = build_evidence_summary(finding, **kwargs)
    assert first.model_dump_json() == second.model_dump_json()
    monkeypatch.setattr("ai_code_security_analyzer.evidence_summary.MAX_EVIDENCE_SUMMARY_BYTES", 1)
    with pytest.raises(EvidenceSummaryError, match="evidence_summary_too_large"):
        build_evidence_summary(finding, **kwargs)


def test_finding_status_is_only_descriptive_and_never_mutated(tmp_path: Path) -> None:
    finding, evidence, scan, summary = _build(tmp_path)
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.confirmation is None
    assert summary.finding_verification_status is finding.status
    assert validate_evidence_summary(
        summary,
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    ) == summary
