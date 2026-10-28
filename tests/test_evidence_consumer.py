"""Consumer boundary tests use only synthetic Semgrep results and rules."""

from __future__ import annotations

import inspect
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from ai_code_security_analyzer.evidence_consumer import (
    EvidenceConsumerError,
    MAX_CONSUMER_RESULT_BYTES,
    ValidationStatus,
    ValidatedEvidence,
    consume_evidence_summary,
)
from ai_code_security_analyzer.evidence_summary import (
    EvidenceSummary,
    FindingKind,
    RuleDeclarationStatus,
    SummaryAssociationStatus,
    SummaryClaim,
    build_evidence_summary,
)
from ai_code_security_analyzer.evidence_sufficiency import ClaimDecision, ClaimType, EvidenceReason
from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import TraceStatus, build_taint_evidence


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
TAINT_RULE_ID = "experimental.javascript-eval-taint"
CANARY = "SYNTHETIC_CONSUMER_CANARY_VALUE"


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
                "start": {"line": 5, "col": 2},
                "end": {"line": 5, "col": 8},
                "extra": {"message": CANARY, "severity": "ERROR", "engine_kind": "OSS", "lines": CANARY},
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


def _build_and_consume(tmp_path: Path, *, taint: bool = True, status: ScanStatus = ScanStatus.COMPLETED):
    finding, evidence, scan = _fixture(tmp_path, taint=taint, status=status)
    summary = build_evidence_summary(
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULE if taint else None,
        trusted_rules_directory=RULES if taint else None,
    )
    consumer = consume_evidence_summary(
        summary,
        finding,
        scan_result=scan,
        evidence=evidence,
        rules_file=TAINT_RULE if taint else None,
        trusted_rules_directory=RULES if taint else None,
    )
    return finding, evidence, scan, summary, consumer


def test_taint_consumer_exposes_only_gate_supported_claims(tmp_path: Path) -> None:
    finding, _evidence, _scan, summary, consumer = _build_and_consume(tmp_path)
    assert consumer.validation_status is ValidationStatus.VALIDATED
    assert consumer.finding_kind is FindingKind.TAINT
    assert consumer.allowed_claim_types == tuple(item.claim_type for item in summary.supported_claims)
    assert set(consumer.allowed_claim_types) == {
        ClaimType.MATCH_REPORTED,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        ClaimType.SOURCE_PATTERN_DECLARED,
        ClaimType.SINK_PATTERN_DECLARED,
        ClaimType.MATCH_LOCATION_OBSERVED,
    }
    assert not consumer.supports(ClaimType.SOURCE_LOCATION_IDENTIFIED)
    assert not consumer.supports(ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED)
    assert not consumer.supports(ClaimType.FLOW_TRACE_AVAILABLE)
    assert not consumer.supports(ClaimType.VULNERABILITY_CONFIRMED)
    assert consumer.decision_for(ClaimType.FLOW_TRACE_AVAILABLE) is ClaimDecision.UNAVAILABLE
    assert EvidenceReason.FLOW_TRACE_ABSENT in consumer.reasons_for(ClaimType.FLOW_TRACE_AVAILABLE)
    assert consumer.finding_id == finding.finding_id
    assert consumer.finding_verification_status is FindingStatus.UNVERIFIED


def test_pattern_consumer_never_upgrades_to_taint(tmp_path: Path) -> None:
    _finding, _evidence, _scan, _summary, consumer = _build_and_consume(tmp_path, taint=False)
    assert consumer.finding_kind is FindingKind.PATTERN
    assert consumer.supports(ClaimType.MATCH_REPORTED)
    assert not consumer.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
    assert consumer.decision_for(ClaimType.TAINT_RULE_MATCH_REPORTED) is ClaimDecision.UNAVAILABLE


def test_unclassified_and_rule_hash_mismatch_remain_restricted(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    changed = replace(evidence, rules_file_sha256="0" * 64)
    summary = build_evidence_summary(
        finding,
        evidence=changed,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    consumer = consume_evidence_summary(
        summary,
        finding,
        evidence=changed,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert consumer.finding_kind is FindingKind.UNCLASSIFIED
    assert consumer.trusted_rule_declaration_status is RuleDeclarationStatus.UNVERIFIED
    assert consumer.supports(ClaimType.MATCH_REPORTED)
    assert not consumer.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
    assert EvidenceReason.RULE_HASH_MISMATCH in consumer.reasons_for(ClaimType.TAINT_RULE_MATCH_REPORTED)


def test_partial_and_failed_scans_do_not_gain_completion_claims(tmp_path: Path) -> None:
    _, _, _, _, partial = _build_and_consume(tmp_path, status=ScanStatus.PARTIAL)
    assert partial.scan_status is ScanStatus.PARTIAL
    assert partial.supports(ClaimType.MATCH_REPORTED)
    assert not partial.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
    match_reasons = partial.reasons_for(ClaimType.MATCH_REPORTED)
    assert EvidenceReason.SCAN_PARTIAL in match_reasons
    assert EvidenceReason.SCAN_PARTIAL in partial.limitations_for(ClaimType.MATCH_REPORTED)

    finding, evidence, scan = _fixture(tmp_path / "failed", status=ScanStatus.TIMED_OUT)
    failed_scan = replace(scan, findings=(), exit_code=None)
    failed_summary = build_evidence_summary(finding, evidence=evidence, scan_result=failed_scan)
    failed = consume_evidence_summary(failed_summary, finding, evidence=evidence, scan_result=failed_scan)
    assert failed.scan_status is ScanStatus.TIMED_OUT
    assert failed.allowed_claims == ()
    assert failed.decision_for(ClaimType.MATCH_REPORTED) is ClaimDecision.UNAVAILABLE


@pytest.mark.parametrize(
    "mutation",
    ["finding_id", "scan_status", "decision", "reason", "provenance", "missing", "duplicate", "added"],
)
def test_summary_mutations_and_context_reuse_are_rejected(tmp_path: Path, mutation: str) -> None:
    finding, evidence, scan, summary, _consumer = _build_and_consume(tmp_path)
    values = summary.model_dump()
    if mutation == "finding_id":
        values["finding_id"] = "semgrep:" + "f" * 24
    elif mutation == "scan_status":
        values["scan_status"] = ScanStatus.PARTIAL
    elif mutation == "decision":
        claims = list(summary.supported_claims)
        claims[0] = claims[0].model_copy(update={"decision": ClaimDecision.UNAVAILABLE})
        values["supported_claims"] = tuple(claims)
    elif mutation == "reason":
        claims = list(summary.restricted_claims)
        claims[0] = claims[0].model_copy(update={"reason_codes": ()})
        values["restricted_claims"] = tuple(claims)
    elif mutation == "provenance":
        claims = list(summary.supported_claims)
        claims[0] = claims[0].model_copy(update={"evidence_provenance": ()})
        values["supported_claims"] = tuple(claims)
    elif mutation == "missing":
        values["restricted_claims"] = summary.restricted_claims[:-1]
    elif mutation == "duplicate":
        values["supported_claims"] = (*summary.supported_claims, summary.supported_claims[0])
    elif mutation == "added":
        claims = list(summary.supported_claims)
        restricted = next(
            item
            for item in summary.restricted_claims
            if item.claim_type is ClaimType.FLOW_TRACE_AVAILABLE
        )
        claims.append(restricted.model_copy(update={"decision": ClaimDecision.SUPPORTED}))
        values["supported_claims"] = tuple(claims)
        values["restricted_claims"] = tuple(item for item in summary.restricted_claims if item is not restricted)
    altered = EvidenceSummary.model_construct(**values)
    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(
            altered,
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )


def test_other_finding_or_scan_cannot_reuse_a_summary(tmp_path: Path) -> None:
    finding, evidence, scan, summary, _consumer = _build_and_consume(tmp_path)
    other_finding = finding.model_copy(update={"finding_id": "semgrep:" + "a" * 24})
    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(summary, other_finding, evidence=evidence, scan_result=scan)
    other_scan = replace(scan, status=ScanStatus.PARTIAL)
    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(
            summary,
            finding,
            evidence=evidence,
            scan_result=other_scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )


def test_rule_change_after_summary_build_rejects_stale_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding, evidence, scan, summary, _consumer = _build_and_consume(tmp_path)
    monkeypatch.setattr(
        "ai_code_security_analyzer.evidence_consumer.validate_evidence_summary",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("unsafe original diagnostic")),
    )
    with pytest.raises(EvidenceConsumerError) as error:
        consume_evidence_summary(
            summary,
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=RULES,
        )
    assert str(error.value) == "evidence_consumer_rejected"
    assert "unsafe original diagnostic" not in str(error.value)


def test_rule_file_change_between_summary_and_consumption_is_rejected(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    trusted_root = tmp_path / "trusted-rules"
    rule_copy = trusted_root / "experimental" / TAINT_RULE.name
    rule_copy.parent.mkdir(parents=True)
    shutil.copyfile(TAINT_RULE, rule_copy)
    summary = build_evidence_summary(
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=rule_copy,
        trusted_rules_directory=trusted_root,
    )
    rule_copy.write_bytes(rule_copy.read_bytes() + b"\n")
    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(
            summary,
            finding,
            evidence=evidence,
            scan_result=scan,
            rules_file=rule_copy,
            trusted_rules_directory=trusted_root,
        )


def test_consumer_requires_originals_and_has_no_bypass_flag() -> None:
    signature = inspect.signature(consume_evidence_summary)
    assert "summary" in signature.parameters
    assert "finding" in signature.parameters
    assert "scan_result" in signature.parameters
    assert "skip_validation" not in signature.parameters
    assert "trusted" not in signature.parameters
    assert "validation_status" not in ValidatedEvidence.model_fields
    with pytest.raises(TypeError, match="use_consume_evidence_summary"):
        ValidatedEvidence(finding_id="semgrep:" + "a" * 24, rule_id="baseline.rule")
    with pytest.raises(TypeError):
        consume_evidence_summary(EvidenceSummary)  # type: ignore[call-arg]


def test_missing_scan_status_is_not_completed_or_authorized(tmp_path: Path) -> None:
    finding, evidence, _scan = _fixture(tmp_path)
    summary = build_evidence_summary(finding, evidence=evidence)
    consumer = consume_evidence_summary(summary, finding, evidence=evidence, scan_result=None)
    assert consumer.scan_status is None
    assert consumer.allowed_claims == ()
    assert consumer.decision_for(ClaimType.MATCH_REPORTED) is ClaimDecision.UNAVAILABLE


@pytest.mark.parametrize("trace_status", [TraceStatus.EMPTY, TraceStatus.UNSUPPORTED])
def test_trace_states_remain_restricted_in_consumer(tmp_path: Path, trace_status: TraceStatus) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    changed = replace(evidence, flow_trace_status=trace_status)
    summary = build_evidence_summary(
        finding,
        evidence=changed,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    consumer = consume_evidence_summary(
        summary,
        finding,
        evidence=changed,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert not consumer.supports(ClaimType.FLOW_TRACE_AVAILABLE)
    assert consumer.decision_for(ClaimType.FLOW_TRACE_AVAILABLE) is ClaimDecision.UNAVAILABLE


def test_ambiguous_duplicate_finding_is_rejected_with_no_allowed_claims(tmp_path: Path) -> None:
    finding, evidence, scan = _fixture(tmp_path)
    duplicate = replace(scan, findings=(finding, finding))
    summary = build_evidence_summary(finding, evidence=evidence, scan_result=duplicate)
    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(summary, finding, evidence=evidence, scan_result=duplicate)


def test_json_round_trip_alone_does_not_create_consumer_result(tmp_path: Path) -> None:
    finding, evidence, scan, summary, _consumer = _build_and_consume(tmp_path)
    decoded = EvidenceSummary.model_validate_json(summary.model_dump_json())
    assert decoded == summary
    with pytest.raises(TypeError):
        consume_evidence_summary(decoded)  # type: ignore[call-arg]
    consumer = consume_evidence_summary(
        decoded,
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert consumer.validation_status is ValidationStatus.VALIDATED


def test_consumer_output_contains_no_source_canary_or_path(tmp_path: Path) -> None:
    _finding, _evidence, _scan, _summary, consumer = _build_and_consume(tmp_path)
    serialized = consumer.model_dump_json()
    assert CANARY not in serialized
    assert "src/synthetic.ts" not in serialized
    assert "/Users/" not in serialized


def test_consumer_output_is_bounded_and_immutable(tmp_path: Path) -> None:
    _finding, _evidence, _scan, _summary, consumer = _build_and_consume(tmp_path)
    assert len(consumer.model_dump_json().encode()) <= MAX_CONSUMER_RESULT_BYTES
    with pytest.raises((AttributeError, TypeError, ValueError)):
        consumer.finding_kind = FindingKind.PATTERN  # type: ignore[misc]
