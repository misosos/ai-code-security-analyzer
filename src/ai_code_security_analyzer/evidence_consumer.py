"""Narrow consumer boundary for validated, internal EvidenceSummary objects."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, computed_field

from ai_code_security_analyzer.evidence_sufficiency import (
    ClaimDecision,
    ClaimType,
    EvidenceReason,
    EvidenceSource,
)
from ai_code_security_analyzer.evidence_summary import (
    MAX_EVIDENCE_SUMMARY_BYTES,
    EvidenceSummary,
    EvidenceSummaryError,
    FindingKind,
    RuleDeclarationStatus,
    SummaryAssociationStatus,
    SummaryClaim,
    validate_evidence_summary,
)
from ai_code_security_analyzer.models import Finding, FindingStatus
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.taint_evidence import TaintEvidence


MAX_CONSUMER_RESULT_BYTES = MAX_EVIDENCE_SUMMARY_BYTES
_CONSUMER_FACTORY_TOKEN = object()


class ValidationStatus(StrEnum):
    VALIDATED = "validated"


class EvidenceConsumerError(ValueError):
    """Fixed error; original validation diagnostics are never propagated."""


class ValidatedEvidence(BaseModel):
    """Bounded snapshot of allowed claims and unchanged claim restrictions.

    This is not a portable trust token. It is valid only as the in-memory result
    of a consumer call for the supplied Finding and scan inputs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    def __init__(self, *, _factory_token: object | None = None, **data: object) -> None:
        if _factory_token is not _CONSUMER_FACTORY_TOKEN:
            raise TypeError("use_consume_evidence_summary")
        super().__init__(**data)

    finding_id: str = Field(min_length=1, max_length=256, strict=True)
    rule_id: str = Field(min_length=1, max_length=256, strict=True)
    finding_kind: FindingKind
    scan_status: ScanStatus | None
    association_status: SummaryAssociationStatus
    engine_name: str | None = Field(default=None, max_length=16, strict=True)
    engine_version: str | None = Field(default=None, max_length=64, strict=True)
    trusted_rule_declaration_status: RuleDeclarationStatus
    allowed_claims: tuple[SummaryClaim, ...] = Field(max_length=len(ClaimType))
    restricted_claims: tuple[SummaryClaim, ...] = Field(max_length=len(ClaimType))
    reason_codes: tuple[EvidenceReason, ...] = Field(max_length=len(ClaimType) * 8)
    evidence_provenance: tuple[EvidenceSource, ...] = Field(max_length=3)
    limitations: tuple[EvidenceReason, ...] = Field(max_length=len(ClaimType) * 8)
    finding_verification_status: FindingStatus

    @computed_field
    @property
    def validation_status(self) -> ValidationStatus:
        """Describe the result returned by the validated consumer function."""
        return ValidationStatus.VALIDATED

    def supports(self, claim_type: ClaimType) -> bool:
        """Return whether the verified Gate explicitly supported this claim."""
        return isinstance(claim_type, ClaimType) and any(
            item.claim_type is claim_type for item in self.allowed_claims
        )

    @property
    def allowed_claim_types(self) -> tuple[ClaimType, ...]:
        return tuple(item.claim_type for item in self.allowed_claims)

    def decision_for(self, claim_type: ClaimType) -> ClaimDecision | None:
        if not isinstance(claim_type, ClaimType):
            return None
        supported = next((item for item in self.allowed_claims if item.claim_type is claim_type), None)
        if supported is not None:
            return ClaimDecision.SUPPORTED
        return next(
            (item.decision for item in self.restricted_claims if item.claim_type is claim_type),
            None,
        )

    def reasons_for(self, claim_type: ClaimType) -> tuple[EvidenceReason, ...]:
        if not isinstance(claim_type, ClaimType):
            return ()
        supported = next((item for item in self.allowed_claims if item.claim_type is claim_type), None)
        if supported is not None:
            return supported.reason_codes
        return next(
            (item.reason_codes for item in self.restricted_claims if item.claim_type is claim_type),
            (),
        )

    def limitations_for(self, claim_type: ClaimType) -> tuple[EvidenceReason, ...]:
        if not isinstance(claim_type, ClaimType):
            return ()
        claim = next(
            (item for item in (*self.allowed_claims, *self.restricted_claims) if item.claim_type is claim_type),
            None,
        )
        return claim.limitations if claim is not None else ()


def _reject() -> EvidenceConsumerError:
    return EvidenceConsumerError("evidence_consumer_rejected")


def consume_evidence_summary(
    summary: EvidenceSummary,
    finding: Finding,
    *,
    scan_result: ScanResult | None,
    evidence: TaintEvidence | None = None,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> ValidatedEvidence:
    """Revalidate original inputs and expose only Gate-supported claim codes.

    There is intentionally no summary-only, trusted-flag, or validation-skip
    overload. Missing scan state is passed explicitly as ``None`` and remains
    unavailable according to the existing Gate.
    """
    try:
        validated = validate_evidence_summary(
            summary,
            finding,
            evidence=evidence,
            scan_result=scan_result,
            rules_file=rules_file,
            trusted_rules_directory=trusted_rules_directory,
        )
        # Ambiguous identity/association is a whole-consumer rejection. Other
        # unavailable claims remain visible in the restricted partition.
        if validated.association_status is SummaryAssociationStatus.AMBIGUOUS:
            raise _reject()

        result = ValidatedEvidence(
            _factory_token=_CONSUMER_FACTORY_TOKEN,
            finding_id=validated.finding_id,
            rule_id=validated.rule_id,
            finding_kind=validated.finding_kind,
            scan_status=validated.scan_status,
            association_status=validated.association_status,
            engine_name=validated.engine_name,
            engine_version=validated.engine_version,
            trusted_rule_declaration_status=validated.trusted_rule_declaration_status,
            allowed_claims=validated.supported_claims,
            restricted_claims=validated.restricted_claims,
            reason_codes=tuple(
                dict.fromkeys(
                    reason
                    for item in validated.restricted_claims
                    for reason in item.reason_codes
                )
            ),
            evidence_provenance=validated.evidence_provenance,
            limitations=validated.limitations,
            finding_verification_status=validated.finding_verification_status,
        )
        if len(result.model_dump_json().encode("utf-8")) > MAX_CONSUMER_RESULT_BYTES:
            raise _reject()
        return result
    except EvidenceConsumerError:
        raise
    except (EvidenceSummaryError, TypeError, ValueError, ValidationError):
        raise _reject() from None
    except Exception:
        # An unexpected validator failure must not leak its diagnostic or
        # produce a partially populated consumer result.
        raise _reject() from None
