"""Deterministic, internal-only sufficiency checks for static-analysis claims.

This module checks evidence structure and provenance. It does not interpret
natural-language security claims or establish exploitability.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from ai_code_security_analyzer.models import Finding
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _finding_id
from ai_code_security_analyzer.taint_evidence import (
    AssociationStatus,
    EvidencePosition,
    EvidenceState,
    TaintEvidence,
    TraceStatus,
    _trusted_declaration,
)


_SEMVER = re.compile(r"\A\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")


class ClaimType(StrEnum):
    MATCH_REPORTED = "match_reported"
    TAINT_RULE_MATCH_REPORTED = "taint_rule_match_reported"
    SOURCE_PATTERN_DECLARED = "source_pattern_declared"
    SINK_PATTERN_DECLARED = "sink_pattern_declared"
    MATCH_LOCATION_OBSERVED = "match_location_observed"
    SOURCE_LOCATION_IDENTIFIED = "source_location_identified"
    SINK_ARGUMENT_LOCATION_IDENTIFIED = "sink_argument_location_identified"
    FLOW_TRACE_AVAILABLE = "flow_trace_available"
    SANITIZER_MATCH_OBSERVED = "sanitizer_match_observed"
    SANITIZER_EFFECTIVENESS_VERIFIED = "sanitizer_effectiveness_verified"
    VULNERABILITY_CONFIRMED = "vulnerability_confirmed"


class ClaimDecision(StrEnum):
    SUPPORTED = "supported"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNAVAILABLE = "unavailable"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED_CLAIM = "unsupported_claim"


class EvidenceSource(StrEnum):
    SEMGREP_OBSERVATION = "semgrep_observation"
    TRUSTED_RULE_DECLARATION = "trusted_rule_declaration"
    ANALYZER_DERIVED = "analyzer_derived"


class EvidenceReason(StrEnum):
    SCAN_STATE_UNAVAILABLE = "scan_state_unavailable"
    SCAN_PARTIAL = "scan_partial"
    SCAN_NOT_COMPLETE = "scan_not_complete"
    SCAN_FAILED = "scan_failed"
    SCAN_RESULT_INCONSISTENT = "scan_result_inconsistent"
    TAINT_EVIDENCE_MALFORMED = "taint_evidence_malformed"
    FINDING_NOT_IN_SCAN = "finding_not_in_scan"
    FINDING_ASSOCIATION_AMBIGUOUS = "finding_association_ambiguous"
    FINDING_ID_MISMATCH = "finding_id_mismatch"
    RULE_ID_MISMATCH = "rule_id_mismatch"
    FILE_PATH_MISMATCH = "file_path_mismatch"
    MATCH_LOCATION_UNAVAILABLE = "match_location_unavailable"
    MATCH_LOCATION_MALFORMED = "match_location_malformed"
    MATCH_LOCATION_NOT_SINK_ARGUMENT = "match_location_not_sink_argument"
    TAINT_EVIDENCE_UNAVAILABLE = "taint_evidence_unavailable"
    ENGINE_UNVERIFIED = "engine_unverified"
    RULE_DECLARATION_UNVERIFIED = "rule_declaration_unverified"
    RULE_HASH_MISMATCH = "rule_hash_mismatch"
    RULE_DECLARATION_MISMATCH = "rule_declaration_mismatch"
    SOURCE_PATTERN_NOT_DECLARED = "source_pattern_not_declared"
    SINK_PATTERN_NOT_DECLARED = "sink_pattern_not_declared"
    SOURCE_LOCATION_UNKNOWN = "source_location_unknown"
    SOURCE_LOCATION_UNAVAILABLE = "source_location_unavailable"
    SOURCE_LOCATION_MALFORMED = "source_location_malformed"
    SOURCE_LOCATION_EVIDENCE_UNAVAILABLE = "source_location_evidence_unavailable"
    SINK_ARGUMENT_LOCATION_UNKNOWN = "sink_argument_location_unknown"
    SINK_ARGUMENT_LOCATION_UNAVAILABLE = "sink_argument_location_unavailable"
    SINK_ARGUMENT_LOCATION_MALFORMED = "sink_argument_location_malformed"
    SINK_ARGUMENT_LOCATION_EVIDENCE_UNAVAILABLE = "sink_argument_location_evidence_unavailable"
    FLOW_TRACE_ABSENT = "flow_trace_absent"
    FLOW_TRACE_EMPTY = "flow_trace_empty"
    FLOW_TRACE_UNSUPPORTED = "flow_trace_unsupported"
    FLOW_TRACE_MALFORMED = "flow_trace_malformed"
    FLOW_TRACE_DETAILS_UNAVAILABLE = "flow_trace_details_unavailable"
    SANITIZER_PATTERN_NOT_DECLARED = "sanitizer_pattern_not_declared"
    SANITIZER_MATCH_UNKNOWN = "sanitizer_match_unknown"
    SANITIZER_MATCH_UNAVAILABLE = "sanitizer_match_unavailable"
    SANITIZER_MATCH_MALFORMED = "sanitizer_match_malformed"
    SANITIZER_MATCH_DETAILS_UNAVAILABLE = "sanitizer_match_details_unavailable"
    SANITIZER_EFFECTIVENESS_NOT_VERIFIED = "sanitizer_effectiveness_not_verified"
    INDEPENDENT_CONFIRMATION_REQUIRED = "independent_confirmation_required"
    RULE_FILE_SCAN_TIME_UNPROVEN = "rule_file_at_scan_time_unproven"
    ANALYSIS_SCOPE_DERIVED = "analysis_scope_derived_from_engine_metadata"
    TAINT_MATCH_NOT_CONFIRMATION = "taint_match_not_vulnerability_confirmation"
    SOURCE_SINK_PATH_UNPROVEN = "source_sink_path_unproven"
    SANITIZER_MATCH_NOT_EFFECTIVENESS = "sanitizer_match_not_effectiveness_proof"
    DECLARATION_NOT_OBSERVATION = "rule_declaration_not_observed_code"
    STATIC_EVIDENCE_CANNOT_SUPPORT_CLAIM = "static_evidence_cannot_support_claim"


class ClaimEvaluation(BaseModel):
    """Safe, closed-vocabulary result for one predefined claim type."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_type: ClaimType
    decision: ClaimDecision
    reason_codes: tuple[EvidenceReason, ...] = Field(max_length=8)
    evidence_provenance: tuple[EvidenceSource, ...] = Field(max_length=3)
    finding_id: str | None = Field(default=None, max_length=256)
    limitations: tuple[EvidenceReason, ...] = Field(max_length=8)


def _safe_relative_path(value: str | None) -> bool:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in value
        and ":" not in value
        and bool(path.parts)
    )


def _valid_position(position) -> bool:
    if not isinstance(position, EvidencePosition) or type(position.line) is not int or position.line < 1:
        return False
    return position.column is None or (type(position.column) is int and position.column > 0)


def _evidence_shape_is_valid(evidence: TaintEvidence) -> bool:
    string_fields = (
        evidence.rule_id,
        evidence.engine_name,
        evidence.analysis_scope,
    )
    optional_string_fields = (
        evidence.finding_id,
        evidence.engine_version,
        evidence.matched_file,
        evidence.rules_file_id,
        evidence.rules_file_sha256,
    )
    tuple_string_fields = (
        evidence.source_patterns_declared,
        evidence.sink_patterns_declared,
        evidence.sanitizer_patterns_declared,
        evidence.observed_json_fields,
        evidence.evidence_provenance,
        evidence.limitations,
    )
    return (
        all(isinstance(value, str) for value in string_fields)
        and all(value is None or isinstance(value, str) for value in optional_string_fields)
        and all(
            isinstance(value, tuple) and all(isinstance(part, str) for part in value)
            for value in tuple_string_fields
        )
        and isinstance(evidence.association_status, AssociationStatus)
        and isinstance(evidence.match_status, EvidenceState)
        and isinstance(evidence.source_declaration_status, EvidenceState)
        and isinstance(evidence.source_location_status, EvidenceState)
        and isinstance(evidence.sink_declaration_status, EvidenceState)
        and isinstance(evidence.sink_location_status, EvidenceState)
        and isinstance(evidence.sanitizer_declaration_status, EvidenceState)
        and isinstance(evidence.sanitizer_match_status, EvidenceState)
        and isinstance(evidence.flow_trace_status, TraceStatus)
        and (evidence.matched_start is None or _valid_position(evidence.matched_start))
        and (evidence.matched_end is None or _valid_position(evidence.matched_end))
        and (evidence.source_location is None or _valid_position(evidence.source_location))
        and (evidence.sink_location is None or _valid_position(evidence.sink_location))
    )


def _range_is_valid(evidence: TaintEvidence) -> bool:
    start, end = evidence.matched_start, evidence.matched_end
    if not _valid_position(start) or not _valid_position(end):
        return False
    assert start is not None and end is not None
    if end.line < start.line:
        return False
    if (
        end.line == start.line
        and start.column is not None
        and end.column is not None
        and end.column < start.column
    ):
        return False
    return True


def _scan_match(finding: Finding, scan_result: ScanResult | None) -> tuple[ClaimDecision | None, list[EvidenceReason]]:
    if scan_result is None:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_STATE_UNAVAILABLE]
    if scan_result.status in {
        ScanStatus.EXECUTION_FAILED,
        ScanStatus.NOT_INSTALLED,
        ScanStatus.INVALID_JSON,
        ScanStatus.TIMED_OUT,
        ScanStatus.OUTPUT_LIMIT_EXCEEDED,
    }:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_FAILED]
    if scan_result.status not in {ScanStatus.PARTIAL, ScanStatus.COMPLETED}:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_STATE_UNAVAILABLE]
    if not isinstance(scan_result.findings, tuple) or not all(
        isinstance(item, Finding) for item in scan_result.findings
    ):
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_RESULT_INCONSISTENT]
    if scan_result.exit_code != 0:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_RESULT_INCONSISTENT]
    if not isinstance(scan_result.semgrep_version, str) or not _SEMVER.fullmatch(scan_result.semgrep_version):
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.ENGINE_UNVERIFIED]
    if scan_result.status is ScanStatus.COMPLETED and scan_result.issues:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_RESULT_INCONSISTENT]
    if finding.source_tool != "semgrep":
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.ENGINE_UNVERIFIED]
    if not _safe_relative_path(finding.file_path):
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.FILE_PATH_MISMATCH]
    if finding.line_number is None or finding.line_number < 1:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.MATCH_LOCATION_UNAVAILABLE]
    matches = [item for item in scan_result.findings if item.finding_id == finding.finding_id]
    if len(matches) > 1:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.FINDING_ASSOCIATION_AMBIGUOUS]
    if not matches:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.FINDING_NOT_IN_SCAN]
    if matches[0] != finding:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.FINDING_ID_MISMATCH]
    if scan_result.status is ScanStatus.PARTIAL:
        return ClaimDecision.SUPPORTED, [EvidenceReason.SCAN_PARTIAL]
    if scan_result.status is ScanStatus.COMPLETED:
        return None, []
    return ClaimDecision.UNAVAILABLE, [EvidenceReason.SCAN_STATE_UNAVAILABLE]


def _evidence_link(
    finding: Finding, evidence: TaintEvidence | None, scan_result: ScanResult | None
) -> tuple[ClaimDecision | None, list[EvidenceReason]]:
    if evidence is None:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.TAINT_EVIDENCE_UNAVAILABLE]
    if evidence.association_status is not AssociationStatus.EXACT:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.FINDING_ASSOCIATION_AMBIGUOUS]
    if evidence.finding_id != finding.finding_id:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.FINDING_ID_MISMATCH]
    if evidence.rule_id != finding.rule_id:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.RULE_ID_MISMATCH]
    if evidence.matched_file != finding.file_path or not _safe_relative_path(evidence.matched_file):
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.FILE_PATH_MISMATCH]
    if finding.line_number is None or not _valid_position(evidence.matched_start):
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.MATCH_LOCATION_UNAVAILABLE]
    if evidence.matched_start.line != finding.line_number:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.MATCH_LOCATION_MALFORMED]
    if evidence.match_status is EvidenceState.MALFORMED or not _range_is_valid(evidence):
        return ClaimDecision.INSUFFICIENT_EVIDENCE, [EvidenceReason.MATCH_LOCATION_MALFORMED]
    if evidence.match_status is not EvidenceState.AVAILABLE:
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.MATCH_LOCATION_UNAVAILABLE]
    if (
        scan_result is None
        or evidence.engine_name != "semgrep"
        or not isinstance(evidence.engine_version, str)
        or not _SEMVER.fullmatch(evidence.engine_version)
        or scan_result.semgrep_version != evidence.engine_version
    ):
        return ClaimDecision.UNAVAILABLE, [EvidenceReason.ENGINE_UNVERIFIED]
    assert evidence.matched_start is not None and evidence.matched_end is not None
    expected_id = _finding_id(
        evidence.rule_id,
        evidence.matched_file,
        evidence.matched_start.line,
        evidence.matched_start.column or 0,
        evidence.matched_end.line,
        evidence.matched_end.column or 0,
    )
    if expected_id != finding.finding_id:
        return ClaimDecision.AMBIGUOUS, [EvidenceReason.FINDING_ID_MISMATCH]
    return None, []


def _trusted_rule_matches(
    evidence: TaintEvidence,
    *,
    rules_file: Path | None,
    trusted_rules_directory: Path | None,
) -> tuple[bool, EvidenceReason | None]:
    if rules_file is None or trusted_rules_directory is None:
        return False, EvidenceReason.RULE_DECLARATION_UNVERIFIED
    declaration = _trusted_declaration(evidence.rule_id, rules_file, trusted_rules_directory)
    sources, sinks, sanitizers, file_id, digest, state = declaration
    if state is not EvidenceState.AVAILABLE:
        reason = (
            EvidenceReason.RULE_HASH_MISMATCH
            if file_id and digest
            else EvidenceReason.RULE_DECLARATION_UNVERIFIED
        )
        return False, reason
    if evidence.rules_file_sha256 != digest:
        return False, EvidenceReason.RULE_HASH_MISMATCH
    if (
        evidence.rules_file_id != file_id
        or evidence.source_patterns_declared != sources
        or evidence.sink_patterns_declared != sinks
        or evidence.sanitizer_patterns_declared != sanitizers
        or evidence.source_declaration_status is not EvidenceState.AVAILABLE
        or evidence.sink_declaration_status is not EvidenceState.AVAILABLE
        or evidence.sanitizer_declaration_status is not EvidenceState.AVAILABLE
    ):
        return False, EvidenceReason.RULE_DECLARATION_MISMATCH
    return True, None


def _engine_is_verified(evidence: TaintEvidence, scan_result: ScanResult | None) -> bool:
    return (
        scan_result is not None
        and scan_result.status is ScanStatus.COMPLETED
        and evidence.engine_name == "semgrep"
        and isinstance(evidence.engine_version, str)
        and _SEMVER.fullmatch(evidence.engine_version) is not None
        and scan_result.semgrep_version == evidence.engine_version
        and evidence.analysis_scope == "per_file"
        and "semgrep_json" in evidence.evidence_provenance
        and "analyzer_oss_scope_mapping" in evidence.evidence_provenance
    )


def _unique(values: list[EvidenceReason]) -> tuple[EvidenceReason, ...]:
    return tuple(dict.fromkeys(values))


def evaluate_claim(
    finding: Finding,
    claim_type: ClaimType,
    *,
    evidence: TaintEvidence | None = None,
    scan_result: ScanResult | None = None,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> ClaimEvaluation:
    """Evaluate one closed claim against a Finding, scan and optional evidence.

    A partial scan may support a particular observed match, but it cannot
    support a taint-rule claim that depends on a complete scan.
    """
    if not isinstance(finding, Finding):
        raise TypeError("finding_must_be_validated")
    if not isinstance(claim_type, ClaimType):
        raise ValueError("unsupported_claim_type")
    if evidence is not None and not isinstance(evidence, TaintEvidence):
        raise TypeError("taint_evidence_must_be_validated")
    if scan_result is not None and not isinstance(scan_result, ScanResult):
        raise TypeError("scan_result_must_be_validated")
    if rules_file is not None and not isinstance(rules_file, Path):
        raise TypeError("rules_file_must_be_local_path")
    if trusted_rules_directory is not None and not isinstance(trusted_rules_directory, Path):
        raise TypeError("trusted_rules_directory_must_be_local_path")

    if claim_type is ClaimType.SANITIZER_EFFECTIVENESS_VERIFIED:
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=ClaimDecision.UNSUPPORTED_CLAIM,
            reason_codes=(EvidenceReason.SANITIZER_EFFECTIVENESS_NOT_VERIFIED,),
            evidence_provenance=(EvidenceSource.ANALYZER_DERIVED,),
            finding_id=finding.finding_id,
            limitations=(EvidenceReason.SANITIZER_EFFECTIVENESS_NOT_VERIFIED,),
        )
    if claim_type is ClaimType.VULNERABILITY_CONFIRMED:
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=ClaimDecision.UNSUPPORTED_CLAIM,
            reason_codes=(EvidenceReason.INDEPENDENT_CONFIRMATION_REQUIRED,),
            evidence_provenance=(EvidenceSource.ANALYZER_DERIVED,),
            finding_id=finding.finding_id,
            limitations=(EvidenceReason.INDEPENDENT_CONFIRMATION_REQUIRED,),
        )

    base_decision, reasons = _scan_match(finding, scan_result)
    provenance: list[EvidenceSource] = []
    if base_decision is None or base_decision is ClaimDecision.SUPPORTED:
        provenance.extend((EvidenceSource.SEMGREP_OBSERVATION, EvidenceSource.ANALYZER_DERIVED))

    if claim_type is ClaimType.MATCH_REPORTED:
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=base_decision or ClaimDecision.SUPPORTED,
            reason_codes=tuple(reasons),
            evidence_provenance=tuple(provenance),
            finding_id=finding.finding_id if base_decision in {None, ClaimDecision.SUPPORTED} else None,
            limitations=tuple(reasons),
        )

    if evidence is not None and not _evidence_shape_is_valid(evidence):
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=ClaimDecision.UNAVAILABLE,
            reason_codes=(EvidenceReason.TAINT_EVIDENCE_MALFORMED,),
            evidence_provenance=(EvidenceSource.ANALYZER_DERIVED,),
            finding_id=None,
            limitations=(EvidenceReason.TAINT_EVIDENCE_MALFORMED,),
        )

    link_decision, link_reasons = _evidence_link(finding, evidence, scan_result)
    if base_decision not in {None, ClaimDecision.SUPPORTED}:
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=base_decision,
            reason_codes=_unique([*reasons, *link_reasons]),
            evidence_provenance=tuple(provenance),
            finding_id=None,
            limitations=_unique([*reasons, *link_reasons]),
        )
    if link_decision is not None:
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=link_decision,
            reason_codes=_unique(link_reasons),
            evidence_provenance=tuple(provenance),
            finding_id=(
                finding.finding_id
                if link_decision in {ClaimDecision.INSUFFICIENT_EVIDENCE, ClaimDecision.AMBIGUOUS}
                else None
            ),
            limitations=_unique(link_reasons),
        )

    assert evidence is not None
    provenance.append(EvidenceSource.SEMGREP_OBSERVATION)
    provenance.append(EvidenceSource.ANALYZER_DERIVED)

    def result(
        decision: ClaimDecision,
        *codes: EvidenceReason,
        rule_source: bool = False,
        limitations: tuple[EvidenceReason, ...] = (),
    ) -> ClaimEvaluation:
        sources = list(provenance)
        if rule_source:
            sources.append(EvidenceSource.TRUSTED_RULE_DECLARATION)
        recorded_limitations = [
            *[reason for reason in reasons if reason is EvidenceReason.SCAN_PARTIAL],
            *limitations,
        ]
        if rule_source:
            recorded_limitations.append(EvidenceReason.RULE_FILE_SCAN_TIME_UNPROVEN)
        return ClaimEvaluation(
            claim_type=claim_type,
            decision=decision,
            reason_codes=_unique(list(codes)),
            evidence_provenance=tuple(dict.fromkeys(sources)),
            finding_id=finding.finding_id,
            limitations=(
                _unique([*recorded_limitations, *codes])
                if decision is not ClaimDecision.SUPPORTED
                else _unique(recorded_limitations)
            ),
        )

    if claim_type is ClaimType.MATCH_LOCATION_OBSERVED:
        return result(
            ClaimDecision.SUPPORTED,
            limitations=(EvidenceReason.MATCH_LOCATION_NOT_SINK_ARGUMENT,),
        )

    if claim_type in {
        ClaimType.SOURCE_PATTERN_DECLARED,
        ClaimType.SINK_PATTERN_DECLARED,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
    }:
        if claim_type is ClaimType.TAINT_RULE_MATCH_REPORTED and (
            scan_result is None or scan_result.status is not ScanStatus.COMPLETED
        ):
            return result(ClaimDecision.INSUFFICIENT_EVIDENCE, *reasons, EvidenceReason.SCAN_NOT_COMPLETE)
        trusted, trust_reason = _trusted_rule_matches(
            evidence, rules_file=rules_file, trusted_rules_directory=trusted_rules_directory
        )
        if not trusted:
            return result(ClaimDecision.UNAVAILABLE, trust_reason or EvidenceReason.RULE_DECLARATION_UNVERIFIED)
        if claim_type is ClaimType.TAINT_RULE_MATCH_REPORTED and not _engine_is_verified(evidence, scan_result):
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.ENGINE_UNVERIFIED, rule_source=True)
        if claim_type is ClaimType.SOURCE_PATTERN_DECLARED:
            if not evidence.source_patterns_declared:
                return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SOURCE_PATTERN_NOT_DECLARED, rule_source=True)
        elif claim_type is ClaimType.SINK_PATTERN_DECLARED:
            if not evidence.sink_patterns_declared:
                return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SINK_PATTERN_NOT_DECLARED, rule_source=True)
        if claim_type is ClaimType.TAINT_RULE_MATCH_REPORTED:
            return result(
                ClaimDecision.SUPPORTED,
                rule_source=True,
                limitations=(
                    EvidenceReason.ANALYSIS_SCOPE_DERIVED,
                    EvidenceReason.SOURCE_SINK_PATH_UNPROVEN,
                    EvidenceReason.TAINT_MATCH_NOT_CONFIRMATION,
                ),
            )
        return result(
            ClaimDecision.SUPPORTED,
            rule_source=True,
            limitations=(EvidenceReason.DECLARATION_NOT_OBSERVATION,),
        )

    if claim_type is ClaimType.SOURCE_LOCATION_IDENTIFIED:
        if evidence.source_location_status is EvidenceState.UNKNOWN:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SOURCE_LOCATION_UNKNOWN)
        if evidence.source_location_status is EvidenceState.MALFORMED:
            return result(ClaimDecision.INSUFFICIENT_EVIDENCE, EvidenceReason.SOURCE_LOCATION_MALFORMED)
        if (
            evidence.source_location_status is not EvidenceState.AVAILABLE
            or not _valid_position(evidence.source_location)
        ):
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SOURCE_LOCATION_UNAVAILABLE)
        if "source_location" not in evidence.observed_json_fields:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SOURCE_LOCATION_EVIDENCE_UNAVAILABLE)
        if not _engine_is_verified(evidence, scan_result):
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.ENGINE_UNVERIFIED)
        return result(ClaimDecision.SUPPORTED)

    if claim_type is ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED:
        if evidence.sink_location_status is EvidenceState.UNKNOWN:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SINK_ARGUMENT_LOCATION_UNKNOWN)
        if evidence.sink_location_status is EvidenceState.MALFORMED:
            return result(ClaimDecision.INSUFFICIENT_EVIDENCE, EvidenceReason.SINK_ARGUMENT_LOCATION_MALFORMED)
        if (
            evidence.sink_location_status is not EvidenceState.AVAILABLE
            or not _valid_position(evidence.sink_location)
        ):
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SINK_ARGUMENT_LOCATION_UNAVAILABLE)
        if "sink_location" not in evidence.observed_json_fields:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SINK_ARGUMENT_LOCATION_EVIDENCE_UNAVAILABLE)
        if not _engine_is_verified(evidence, scan_result):
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.ENGINE_UNVERIFIED)
        return result(ClaimDecision.SUPPORTED)

    if claim_type is ClaimType.FLOW_TRACE_AVAILABLE:
        trace_status = evidence.flow_trace_status
        if not isinstance(trace_status, TraceStatus):
            trace_status = TraceStatus.MALFORMED
        trace_reasons = {
            TraceStatus.ABSENT: EvidenceReason.FLOW_TRACE_ABSENT,
            TraceStatus.EMPTY: EvidenceReason.FLOW_TRACE_EMPTY,
            TraceStatus.MALFORMED: EvidenceReason.FLOW_TRACE_MALFORMED,
            TraceStatus.UNSUPPORTED: EvidenceReason.FLOW_TRACE_UNSUPPORTED,
            TraceStatus.NOT_EVALUATED: EvidenceReason.FLOW_TRACE_DETAILS_UNAVAILABLE,
            TraceStatus.AVAILABLE: EvidenceReason.FLOW_TRACE_DETAILS_UNAVAILABLE,
        }
        return result(ClaimDecision.UNAVAILABLE, trace_reasons[trace_status])

    if claim_type is ClaimType.SANITIZER_MATCH_OBSERVED:
        if not evidence.sanitizer_patterns_declared:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SANITIZER_PATTERN_NOT_DECLARED)
        if evidence.sanitizer_match_status is EvidenceState.UNKNOWN:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SANITIZER_MATCH_UNKNOWN)
        if evidence.sanitizer_match_status is EvidenceState.MALFORMED:
            return result(ClaimDecision.INSUFFICIENT_EVIDENCE, EvidenceReason.SANITIZER_MATCH_MALFORMED)
        if evidence.sanitizer_match_status is not EvidenceState.AVAILABLE:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SANITIZER_MATCH_UNAVAILABLE)
        trusted, trust_reason = _trusted_rule_matches(
            evidence, rules_file=rules_file, trusted_rules_directory=trusted_rules_directory
        )
        if not trusted:
            return result(ClaimDecision.UNAVAILABLE, trust_reason or EvidenceReason.RULE_DECLARATION_UNVERIFIED)
        if not _engine_is_verified(evidence, scan_result):
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.ENGINE_UNVERIFIED, rule_source=True)
        if "sanitizer_match" not in evidence.observed_json_fields:
            return result(ClaimDecision.UNAVAILABLE, EvidenceReason.SANITIZER_MATCH_DETAILS_UNAVAILABLE)
        return result(
            ClaimDecision.SUPPORTED,
            rule_source=True,
            limitations=(EvidenceReason.SANITIZER_MATCH_NOT_EFFECTIVENESS,),
        )

    return result(ClaimDecision.UNSUPPORTED_CLAIM, EvidenceReason.STATIC_EVIDENCE_CANNOT_SUPPORT_CLAIM)


def evaluate_all_claims(
    finding: Finding,
    *,
    evidence: TaintEvidence | None = None,
    scan_result: ScanResult | None = None,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> tuple[ClaimEvaluation, ...]:
    """Return deterministic assessments for every supported claim vocabulary."""
    return tuple(
        evaluate_claim(
            finding,
            claim,
            evidence=evidence,
            scan_result=scan_result,
            rules_file=rules_file,
            trusted_rules_directory=trusted_rules_directory,
        )
        for claim in ClaimType
    )
