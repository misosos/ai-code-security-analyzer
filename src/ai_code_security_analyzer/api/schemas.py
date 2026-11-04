"""Closed DTOs for the local API; public analyzer models are never serialized."""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from ai_code_security_analyzer.evidence_sufficiency import ClaimDecision, ClaimType, EvidenceReason
from ai_code_security_analyzer.evidence_summary import FindingKind
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.models import Severity


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HealthResponse(ClosedModel):
    status: str = "ok"
    service: str = "ai-code-security-analyzer"


class TargetOption(ClosedModel):
    id: str
    label: str


class RuleProfileOption(ClosedModel):
    id: str
    label: str
    experimental: bool


class OptionsResponse(ClosedModel):
    targets: tuple[TargetOption, ...]
    rule_profiles: tuple[RuleProfileOption, ...]


class ScanRequest(ClosedModel):
    target_id: StrictStr = Field(min_length=1, max_length=64)
    rule_profile_id: StrictStr = Field(min_length=1, max_length=64)


class InvestigationScanRequest(ScanRequest):
    """Closed request for one evidence-backed scan on the supported launcher."""


class InvestigationCreateRequest(ClosedModel):
    baseline_handle: StrictStr = Field(min_length=43, max_length=43, pattern=r"\A[A-Za-z0-9_-]{43}\z")
    current_handle: StrictStr = Field(min_length=43, max_length=43, pattern=r"\A[A-Za-z0-9_-]{43}\z")


class InvestigationEvaluateRequest(ClosedModel):
    investigation_handle: StrictStr = Field(min_length=43, max_length=43, pattern=r"\A[A-Za-z0-9_-]{43}\z")


class InvestigationReleaseRequest(ClosedModel):
    kind: Literal["run", "investigation"]
    handle: StrictStr = Field(min_length=43, max_length=43, pattern=r"\A[A-Za-z0-9_-]{43}\z")


class InvestigationScanResponse(ClosedModel):
    contract_version: Literal["investigation-scan/v1"]
    run_handle: str = Field(pattern=r"\A[A-Za-z0-9_-]{43}\z")
    scan: ScanResponse


class InvestigationSessionResponse(ClosedModel):
    contract_version: Literal["investigation-session/v1"]
    investigation_handle: str = Field(pattern=r"\A[A-Za-z0-9_-]{43}\z")


class InvestigationFindingEvaluation(ClosedModel):
    finding_id: str = Field(pattern=r"\Asemgrep:[a-f0-9]{24}\z")
    category: Literal["currentOnly", "shared", "baselineOnly"]
    path_observation: Literal[
        "PATH_REPORTED_SCANNED", "PATH_EXPLICITLY_SKIPPED", "PATH_NOT_REPORTED",
        "SKIP_EVIDENCE_NOT_COLLECTED", "SCOPE_EVIDENCE_UNAVAILABLE",
        "FINDING_PATH_UNAVAILABLE", "CONFLICTING",
    ] | None
    skip_hypothesis: Literal[
        "COMPARABLE", "SUPPORTED", "CONTRADICTED", "UNDETERMINED", "INCOMPARABLE",
        "EXPLANATION_SUPPORTED", "MULTIPLE_EXPLANATIONS_POSSIBLE",
    ] | None
    source_snapshot_hypothesis: Literal[
        "COMPARABLE", "SUPPORTED", "CONTRADICTED", "UNDETERMINED", "INCOMPARABLE",
        "EXPLANATION_SUPPORTED", "MULTIPLE_EXPLANATIONS_POSSIBLE",
    ] | None
    rule_identity_hypothesis: Literal[
        "COMPARABLE", "SUPPORTED", "CONTRADICTED", "UNDETERMINED", "INCOMPARABLE",
        "EXPLANATION_SUPPORTED", "MULTIPLE_EXPLANATIONS_POSSIBLE",
    ] | None


class InvestigationEvaluationResponse(ClosedModel):
    contract_version: Literal["finding-disappearance-evaluation/v1"]
    comparability: Literal[
        "COMPARABLE", "SUPPORTED", "CONTRADICTED", "UNDETERMINED", "INCOMPARABLE",
        "EXPLANATION_SUPPORTED", "MULTIPLE_EXPLANATIONS_POSSIBLE",
    ]
    overall_assessment: Literal[
        "COMPARABLE", "SUPPORTED", "CONTRADICTED", "UNDETERMINED", "INCOMPARABLE",
        "EXPLANATION_SUPPORTED", "MULTIPLE_EXPLANATIONS_POSSIBLE",
    ]
    findings: tuple[InvestigationFindingEvaluation, ...] = Field(max_length=100)
    limitation_codes: tuple[Literal[
        "scan_context_mismatch", "scan_reference_collision", "manifest_binding_invalid",
        "response_manifest_binding_invalid", "duplicate_finding_id", "finding_id_not_observed",
        "scan_incomplete", "finding_omitted", "rule_bytes_unverified",
        "loaded_rule_identity_unverified", "source_snapshot_not_collected",
        "scope_completeness_unverified", "path_reported_scanned", "path_explicitly_skipped",
        "path_not_reported", "skip_details_not_collected", "scope_evidence_unavailable",
        "finding_path_unavailable", "scanned_skipped_path_conflict",
        "evaluation_output_limit_exceeded", "scan_result_is_not_safety_proof",
    ], ...] = Field(max_length=64)


class RestrictedClaim(ClosedModel):
    claim_type: ClaimType
    decision: Literal[
        ClaimDecision.INSUFFICIENT_EVIDENCE,
        ClaimDecision.UNAVAILABLE,
        ClaimDecision.AMBIGUOUS,
        ClaimDecision.UNSUPPORTED_CLAIM,
    ]
    reason_codes: tuple[EvidenceReason, ...] = Field(max_length=8)


class ApiFinding(ClosedModel):
    finding_id: str = Field(min_length=1, max_length=64, pattern=r"\Asemgrep:[a-f0-9]{24}\z")
    rule_id: str = Field(min_length=1, max_length=256, pattern=r"\A[A-Za-z0-9_.:-]+\z")
    severity: Severity
    verification_status: Literal["unverified"] = "unverified"
    finding_kind: FindingKind
    file_path: str | None = Field(default=None, max_length=512)
    line_number: int | None = Field(default=None, ge=1)
    evidence_validation_status: Literal["validated", "rejected", "unavailable"]
    supported_claims: tuple[ClaimType, ...] = Field(max_length=len(ClaimType))
    restricted_claims: tuple[RestrictedClaim, ...] = Field(max_length=len(ClaimType))
    validation_error_code: str | None = Field(default=None, pattern=r"\A[a-z_]{1,64}\z")

    @field_validator("file_path")
    @classmethod
    def safe_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value or value.startswith("/") or "\\" in value or ":" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or len(value) > 512 or any(unicodedata.category(char).startswith("C") for char in value)
        ):
            raise ValueError("unsafe_relative_path")
        return value


class IssueCode(StrEnum):
    SEMGREP_NOT_INSTALLED = "semgrep_not_installed"
    SEMGREP_TIMEOUT = "semgrep_timeout"
    SEMGREP_OUTPUT_LIMIT = "semgrep_output_limit"
    INVALID_JSON = "invalid_json"
    SEMGREP_FAILED = "semgrep_failed"
    FINDINGS_OMITTED = "findings_omitted"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"


class LimitationCode(StrEnum):
    FINDING_COUNT_NOT_CONFIRMED = "finding_count_not_confirmed_vulnerability_count"
    SCAN_RESULT_IS_NOT_SAFETY_PROOF = "scan_result_is_not_safety_proof"
    SCAN_PARTIAL = "scan_partial"
    SCAN_FAILED = "scan_failed"
    OMITTED_NOT_VALIDATED = "omitted_findings_not_individually_validated"


class ScanResponse(ClosedModel):
    scan_status: ScanStatus
    completed: bool
    semgrep_version: str | None = Field(default=None, max_length=64, pattern=r"\A\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\z")
    finding_count: int = Field(ge=0)
    displayed_finding_count: int = Field(ge=0, le=50)
    omitted_finding_count: int = Field(ge=0)
    severity_counts: dict[Severity, int]
    issues: tuple[IssueCode, ...]
    findings: tuple[ApiFinding, ...] = Field(max_length=50)
    limitations: tuple[LimitationCode, ...]


class ErrorResponse(ClosedModel):
    error: str
