"""Validated, internal-only summaries of Evidence Sufficiency Gate results."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ai_code_security_analyzer.evidence_sufficiency import (
    ClaimDecision,
    ClaimEvaluation,
    ClaimType,
    EvidenceReason,
    EvidenceSource,
    evaluate_all_claims,
)
from ai_code_security_analyzer.models import Finding, FindingStatus
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.taint_evidence import AssociationStatus, TaintEvidence


MAX_EVIDENCE_SUMMARY_BYTES = 16_384
_SAFE_IDENTIFIER = re.compile(r"\A[A-Za-z0-9_.:-]{1,256}\Z")
_FINDING_ID = re.compile(r"\Asemgrep:[a-f0-9]{24}\Z")


class FindingKind(StrEnum):
    PATTERN = "pattern"
    TAINT = "taint"
    UNCLASSIFIED = "unclassified"


class RuleDeclarationStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    NOT_APPLICABLE = "not_applicable"


class SummaryAssociationStatus(StrEnum):
    EXACT = "exact"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class EvidenceSummaryError(ValueError):
    """Safe, fixed error for rejected or oversized summaries."""


class SummaryClaim(BaseModel):
    """One copied Gate decision; it contains no source text or paths."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_type: ClaimType
    decision: ClaimDecision
    reason_codes: tuple[EvidenceReason, ...] = Field(max_length=8)
    evidence_provenance: tuple[EvidenceSource, ...] = Field(max_length=3)
    finding_id: str | None = Field(default=None, max_length=256)
    limitations: tuple[EvidenceReason, ...] = Field(max_length=8)

    @field_validator("finding_id")
    @classmethod
    def identifier_is_safe(cls, value: str | None) -> str | None:
        if value is not None and not _FINDING_ID.fullmatch(value):
            raise ValueError("unsafe_identifier")
        return value

    def to_gate_evaluation(self) -> ClaimEvaluation:
        """Reconstitute the exact Gate record for an independent comparison."""
        return ClaimEvaluation(
            claim_type=self.claim_type,
            decision=self.decision,
            reason_codes=self.reason_codes,
            evidence_provenance=self.evidence_provenance,
            finding_id=self.finding_id,
            limitations=self.limitations,
        )


class EvidenceSummary(BaseModel):
    """Closed, bounded transfer representation; not itself a trusted token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1, max_length=256, strict=True)
    rule_id: str = Field(min_length=1, max_length=256, strict=True)
    finding_kind: FindingKind
    scan_status: ScanStatus | None
    association_status: SummaryAssociationStatus
    engine_name: Literal["semgrep"] | None
    engine_version: str | None = Field(default=None, max_length=64, strict=True)
    match_observation_status: ClaimDecision
    trusted_rule_declaration_status: RuleDeclarationStatus
    supported_claims: tuple[SummaryClaim, ...] = Field(max_length=len(ClaimType))
    restricted_claims: tuple[SummaryClaim, ...] = Field(max_length=len(ClaimType))
    evidence_provenance: tuple[EvidenceSource, ...] = Field(max_length=3)
    limitations: tuple[EvidenceReason, ...] = Field(max_length=len(ClaimType) * 8)
    finding_verification_status: FindingStatus

    @field_validator("finding_id")
    @classmethod
    def finding_identifier_is_opaque(cls, value: str) -> str:
        if not _FINDING_ID.fullmatch(value):
            raise ValueError("unsafe_finding_identifier")
        return value

    @field_validator("rule_id")
    @classmethod
    def rule_identifier_is_safe(cls, value: str) -> str:
        if not _SAFE_IDENTIFIER.fullmatch(value):
            raise ValueError("unsafe_rule_identifier")
        return value

    @field_validator("engine_version")
    @classmethod
    def version_is_safe(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", value):
            raise ValueError("unsafe_engine_version")
        return value

    @model_validator(mode="after")
    def all_claims_are_partitioned(self) -> EvidenceSummary:
        supported = self.supported_claims
        restricted = self.restricted_claims
        combined = (*supported, *restricted)
        types = tuple(item.claim_type for item in combined)
        if len(types) != len(ClaimType) or len(set(types)) != len(ClaimType) or set(types) != set(ClaimType):
            raise ValueError("summary_claim_partition_incomplete")
        if any(item.decision is not ClaimDecision.SUPPORTED for item in supported):
            raise ValueError("unsupported_claim_in_supported_partition")
        if any(item.decision is ClaimDecision.SUPPORTED for item in restricted):
            raise ValueError("supported_claim_in_restricted_partition")
        if len(set(self.evidence_provenance)) != len(self.evidence_provenance):
            raise ValueError("duplicate_provenance")
        if len(set(self.limitations)) != len(self.limitations):
            raise ValueError("duplicate_limitation")
        if any(item.finding_id not in {None, self.finding_id} for item in combined):
            raise ValueError("claim_finding_mismatch")
        if self.finding_kind is FindingKind.TAINT and (
            self.trusted_rule_declaration_status is not RuleDeclarationStatus.VERIFIED
        ):
            raise ValueError("taint_kind_without_verified_declaration")
        if self.association_status is SummaryAssociationStatus.EXACT and not any(
            item.claim_type is ClaimType.MATCH_LOCATION_OBSERVED and item.decision is ClaimDecision.SUPPORTED
            for item in combined
        ):
            raise ValueError("exact_association_without_supported_match_location")
        return self


def _safe_error() -> EvidenceSummaryError:
    return EvidenceSummaryError("evidence_summary_validation_failed")


def _summarize_gate(
    finding: Finding,
    evaluations: tuple[ClaimEvaluation, ...],
    *,
    evidence: TaintEvidence | None,
    scan_result: ScanResult | None,
) -> EvidenceSummary:
    if len(evaluations) != len(ClaimType) or {item.claim_type for item in evaluations} != set(ClaimType):
        raise _safe_error()

    supported: list[SummaryClaim] = []
    restricted: list[SummaryClaim] = []
    provenance: list[EvidenceSource] = []
    limitations: list[EvidenceReason] = []
    for item in evaluations:
        copied = SummaryClaim(
            claim_type=item.claim_type,
            decision=item.decision,
            reason_codes=item.reason_codes,
            evidence_provenance=item.evidence_provenance,
            finding_id=item.finding_id,
            limitations=item.limitations,
        )
        (supported if item.decision is ClaimDecision.SUPPORTED else restricted).append(copied)
        provenance.extend(item.evidence_provenance)
        limitations.extend(item.limitations)

    by_type = {item.claim_type: item for item in evaluations}
    declaration_claims = (
        by_type[ClaimType.SOURCE_PATTERN_DECLARED],
        by_type[ClaimType.SINK_PATTERN_DECLARED],
    )
    declaration_verified = any(item.decision is ClaimDecision.SUPPORTED for item in declaration_claims)
    declaration_status = (
        RuleDeclarationStatus.VERIFIED
        if declaration_verified
        else RuleDeclarationStatus.UNVERIFIED
        if evidence is not None
        else RuleDeclarationStatus.NOT_APPLICABLE
    )
    finding_kind = (
        FindingKind.TAINT
        if declaration_verified or by_type[ClaimType.TAINT_RULE_MATCH_REPORTED].decision is ClaimDecision.SUPPORTED
        else FindingKind.PATTERN
        if evidence is None
        else FindingKind.UNCLASSIFIED
    )
    if any(
        EvidenceReason.FINDING_ASSOCIATION_AMBIGUOUS in item.reason_codes
        or EvidenceReason.FINDING_ID_MISMATCH in item.reason_codes
        or EvidenceReason.RULE_ID_MISMATCH in item.reason_codes
        or EvidenceReason.FILE_PATH_MISMATCH in item.reason_codes
        for item in evaluations
    ):
        association = SummaryAssociationStatus.AMBIGUOUS
    elif evidence is None:
        association = SummaryAssociationStatus.NOT_APPLICABLE
    elif by_type[ClaimType.MATCH_LOCATION_OBSERVED].decision is ClaimDecision.SUPPORTED:
        association = SummaryAssociationStatus.EXACT
    else:
        association = SummaryAssociationStatus.UNAVAILABLE

    match_claim = by_type[ClaimType.MATCH_REPORTED]
    scan_status = (
        scan_result.status
        if scan_result is not None and isinstance(scan_result.status, ScanStatus)
        else None
    )
    version = scan_result.semgrep_version if scan_result is not None else None
    if version is not None and not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
        version = None
    engine_name = "semgrep" if finding.source_tool == "semgrep" else None
    summary = EvidenceSummary(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        finding_kind=finding_kind,
        scan_status=scan_status,
        association_status=association,
        engine_name=engine_name,
        engine_version=version,
        match_observation_status=match_claim.decision,
        trusted_rule_declaration_status=declaration_status,
        supported_claims=tuple(supported),
        restricted_claims=tuple(restricted),
        evidence_provenance=tuple(dict.fromkeys(provenance)),
        limitations=tuple(dict.fromkeys(limitations)),
        finding_verification_status=finding.status,
    )
    if len(summary.model_dump_json().encode("utf-8")) > MAX_EVIDENCE_SUMMARY_BYTES:
        raise EvidenceSummaryError("evidence_summary_too_large")
    return summary


def build_evidence_summary(
    finding: Finding,
    *,
    evidence: TaintEvidence | None = None,
    scan_result: ScanResult | None = None,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> EvidenceSummary:
    """Run the existing Gate and copy its complete claim set into a summary."""
    if not isinstance(finding, Finding):
        raise EvidenceSummaryError("evidence_summary_validation_failed")
    try:
        evaluations = evaluate_all_claims(
            finding,
            evidence=evidence,
            scan_result=scan_result,
            rules_file=rules_file,
            trusted_rules_directory=trusted_rules_directory,
        )
        return _summarize_gate(finding, evaluations, evidence=evidence, scan_result=scan_result)
    except EvidenceSummaryError:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _safe_error() from None


def validate_evidence_summary(
    summary: EvidenceSummary,
    finding: Finding,
    *,
    evidence: TaintEvidence | None = None,
    scan_result: ScanResult | None = None,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> EvidenceSummary:
    """Recompute the Gate and require exact summary equality before use."""
    if not isinstance(summary, EvidenceSummary):
        raise _safe_error()
    expected = build_evidence_summary(
        finding,
        evidence=evidence,
        scan_result=scan_result,
        rules_file=rules_file,
        trusted_rules_directory=trusted_rules_directory,
    )
    if summary != expected:
        raise _safe_error()
    return summary
