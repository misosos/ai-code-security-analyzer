"""Internal, source-aware metadata for Semgrep OSS taint matches.

This module records declarations and observations separately. It deliberately
does not reconstruct source-to-sink paths from Semgrep's match location.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from ai_code_security_analyzer.models import Finding
from ai_code_security_analyzer.semgrep_parser import _finding_id


_EXPECTED_RULE_FILE = "experimental/javascript-eval-taint.yml"
_EXPECTED_RULES_SHA256 = "6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e"
_MAX_RULE_FILE_BYTES = 256_000
_RULE_DECLARATIONS: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "experimental.javascript-eval-taint": (
        ("$REQ.query.code", "$REQ.body.code"),
        ("eval($CODE)",),
        (),
    ),
    "experimental.javascript-eval-taint-with-synthetic-sanitizer": (
        ("$REQ.query.code", "$REQ.body.code"),
        ("eval($CODE)",),
        ("syntheticSafe($VALUE)",),
    ),
}
_VERSION_RE = re.compile(r"\A\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")


class EvidenceState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    MALFORMED = "malformed"


class TraceStatus(StrEnum):
    AVAILABLE = "available"
    ABSENT = "absent"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    NOT_EVALUATED = "not_evaluated"


class AssociationStatus(StrEnum):
    EXACT = "exact"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class EvidencePosition:
    line: int
    column: int | None = None


@dataclass(frozen=True)
class TaintEvidence:
    """Internal evidence record; code excerpts and arbitrary messages are absent."""

    finding_id: str | None
    association_status: AssociationStatus
    rule_id: str
    engine_name: str
    engine_version: str | None
    analysis_scope: str
    matched_file: str | None
    matched_start: EvidencePosition | None
    matched_end: EvidencePosition | None
    match_status: EvidenceState
    source_patterns_declared: tuple[str, ...]
    source_declaration_status: EvidenceState
    source_location: EvidencePosition | None
    source_location_status: EvidenceState
    sink_patterns_declared: tuple[str, ...]
    sink_declaration_status: EvidenceState
    sink_location: EvidencePosition | None
    sink_location_status: EvidenceState
    flow_trace_status: TraceStatus
    sanitizer_patterns_declared: tuple[str, ...]
    sanitizer_declaration_status: EvidenceState
    sanitizer_match_status: EvidenceState
    rules_file_id: str | None
    rules_file_sha256: str | None
    observed_json_fields: tuple[str, ...]
    evidence_provenance: tuple[str, ...]
    limitations: tuple[str, ...]


def _positive_int(value: Any) -> int | None:
    return value if type(value) is int and value > 0 else None


def _position(value: Any) -> EvidencePosition | None:
    if not isinstance(value, dict):
        return None
    line = _positive_int(value.get("line"))
    column = _positive_int(value.get("col"))
    return EvidencePosition(line, column) if line is not None else None


def _finding_identity_matches(finding: Finding, item: dict[str, Any], path: str | None) -> bool:
    if path is None:
        return False
    start = item.get("start")
    end = item.get("end")
    start = start if isinstance(start, dict) else {}
    end = end if isinstance(end, dict) else {}
    line = _positive_int(start.get("line"))
    if line is None:
        return False
    column = _positive_int(start.get("col")) or 0
    end_line = _positive_int(end.get("line")) or 0
    end_column = _positive_int(end.get("col")) or 0
    return finding.finding_id == _finding_id(finding.rule_id, path, line, column, end_line, end_column)


def _relative_path(raw: Any, project_root: Path) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        return None
    try:
        resolved = (project_root / raw).resolve()
        relative = resolved.relative_to(project_root).as_posix()
    except (OSError, ValueError, RuntimeError):
        return None
    return relative if relative not in {"", "."} else None


def _trace_status(item: dict[str, Any]) -> TraceStatus:
    extra = item.get("extra")
    candidates: list[Any] = []
    found = False
    for container in (item, extra if isinstance(extra, dict) else {}):
        for key in ("dataflow_trace", "taint_trace", "trace"):
            if key in container:
                found = True
                candidates.append(container[key])
    if not found:
        return TraceStatus.ABSENT
    # No Semgrep 1.182.1 OSS trace schema is accepted by this contract yet.
    # Inspect only the outer type and never retain the provided value.
    if any(not isinstance(value, (dict, list)) for value in candidates):
        return TraceStatus.MALFORMED
    return TraceStatus.UNSUPPORTED


def _trusted_declaration(
    rule_id: str,
    rules_file: Path | None,
    trusted_rules_directory: Path | None,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str | None, str | None, EvidenceState]:
    declaration = _RULE_DECLARATIONS.get(rule_id)
    if declaration is None or rules_file is None or trusted_rules_directory is None:
        return (), (), (), None, None, EvidenceState.UNAVAILABLE
    try:
        trusted_root = trusted_rules_directory.resolve(strict=True)
        resolved_file = rules_file.resolve(strict=True)
        relative = resolved_file.relative_to(trusted_root).as_posix()
        if (
            relative != _EXPECTED_RULE_FILE
            or not resolved_file.is_file()
            or resolved_file.stat().st_size > _MAX_RULE_FILE_BYTES
        ):
            return (), (), (), None, None, EvidenceState.UNAVAILABLE
        with resolved_file.open("rb") as source:
            contents = source.read(_MAX_RULE_FILE_BYTES + 1)
        if len(contents) > _MAX_RULE_FILE_BYTES:
            return (), (), (), relative, None, EvidenceState.UNAVAILABLE
        digest = hashlib.sha256(contents).hexdigest()
    except (OSError, ValueError, RuntimeError):
        return (), (), (), None, None, EvidenceState.UNAVAILABLE
    if digest != _EXPECTED_RULES_SHA256:
        return (), (), (), relative, digest, EvidenceState.UNAVAILABLE
    return (*declaration, relative, digest, EvidenceState.AVAILABLE)


def build_taint_evidence(
    document: dict[str, Any],
    result_findings: tuple[Finding | None, ...],
    project_root: Path,
    *,
    rules_file: Path | None,
    trusted_rules_directory: Path | None,
) -> tuple[TaintEvidence, ...]:
    """Build internal records from the same bounded JSON used for Findings.

    ``result_findings`` has one slot per raw Semgrep result, preserving exact
    result association. Duplicate deterministic Finding IDs are marked
    ambiguous and are not joined to a Finding ID.
    """

    raw_results = document.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != len(result_findings):
        return ()
    root = project_root.resolve()
    id_counts: dict[str, int] = {}
    for finding in result_findings:
        if finding is not None:
            id_counts[finding.finding_id] = id_counts.get(finding.finding_id, 0) + 1

    requested_engine = document.get("engine_requested")
    version_value = document.get("version")
    version = version_value if isinstance(version_value, str) and _VERSION_RE.fullmatch(version_value) else None
    evidence: list[TaintEvidence] = []
    declaration_cache: dict[
        str,
        tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str | None, str | None, EvidenceState],
    ] = {}
    for item, finding in zip(raw_results, result_findings, strict=True):
        if not isinstance(item, dict):
            continue
        rule_id = item.get("check_id")
        if not isinstance(rule_id, str) or rule_id not in _RULE_DECLARATIONS:
            continue
        extra = item.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        engine_kind = extra.get("engine_kind")
        matched_file = _relative_path(item.get("path"), root)
        start = _position(item.get("start"))
        end = _position(item.get("end"))
        location_malformed = (
            item.get("start") is not None and start is None
        ) or (item.get("end") is not None and end is None)
        if start is not None and end is not None and (
            end.line < start.line
            or (end.line == start.line and end.column is not None and start.column is not None and end.column < start.column)
        ):
            location_malformed = True
            end = None
        match_available = matched_file is not None and start is not None and not location_malformed
        if rule_id not in declaration_cache:
            declaration_cache[rule_id] = _trusted_declaration(rule_id, rules_file, trusted_rules_directory)
        patterns = declaration_cache[rule_id]
        sources, sinks, sanitizers, rules_file_id, rules_sha256, declaration_status = patterns

        finding_matches_result = (
            finding is not None
            and finding.rule_id == rule_id
            and finding.file_path == matched_file
            and finding.line_number == (start.line if start else None)
            and _finding_identity_matches(finding, item, matched_file)
        )
        association = (
            AssociationStatus.EXACT
            if finding_matches_result and id_counts.get(finding.finding_id, 0) == 1
            else AssociationStatus.AMBIGUOUS
        )
        linked_finding_id = finding.finding_id if finding is not None and association is AssociationStatus.EXACT else None
        if finding is None:
            association = AssociationStatus.AMBIGUOUS

        limitations: list[str] = [
            "source_location_not_emitted",
            "sink_argument_location_not_emitted",
            "flow_trace_not_emitted_or_not_supported",
            "taint_match_does_not_confirm_vulnerability",
        ]
        if end is None:
            limitations.append("match_end_unavailable")
        if declaration_status is not EvidenceState.AVAILABLE:
            limitations.append("trusted_rule_declaration_unavailable")
        if association is AssociationStatus.AMBIGUOUS:
            limitations.append("finding_association_ambiguous")
        if not match_available:
            limitations.append("match_location_unavailable")

        observed = ["check_id"]
        if matched_file is not None:
            observed.append("path")
        if start is not None:
            observed.append("start")
        if end is not None:
            observed.append("end")
        if isinstance(extra.get("severity"), str):
            observed.append("extra.severity")
        metadata = extra.get("metadata")
        if isinstance(metadata, dict) and "cwe" in metadata:
            observed.append("extra.metadata.cwe")
        if isinstance(engine_kind, str):
            observed.append("extra.engine_kind")

        engine_name = "semgrep"
        scope = "per_file" if requested_engine == "OSS" and engine_kind == "OSS" else "unknown"
        provenance = ["semgrep_json", "trusted_rule_sha256" if declaration_status is EvidenceState.AVAILABLE else "rule_declaration_unverified", "analyzer_association"]
        if scope == "per_file":
            provenance.append("analyzer_oss_scope_mapping")
            limitations.append("analysis_scope_derived_from_oss_engine")
        trace_status = _trace_status(item)
        if trace_status in {TraceStatus.MALFORMED, TraceStatus.UNSUPPORTED}:
            limitations.append("trace_structure_not_supported")
        evidence.append(TaintEvidence(
            finding_id=linked_finding_id,
            association_status=association,
            rule_id=rule_id,
            engine_name=engine_name,
            engine_version=version,
            analysis_scope=scope,
            matched_file=matched_file,
            matched_start=start,
            matched_end=end,
            match_status=EvidenceState.AVAILABLE if match_available else (EvidenceState.MALFORMED if location_malformed else EvidenceState.UNAVAILABLE),
            source_patterns_declared=sources,
            source_declaration_status=declaration_status,
            source_location=None,
            source_location_status=EvidenceState.UNKNOWN,
            sink_patterns_declared=sinks,
            sink_declaration_status=declaration_status,
            sink_location=None,
            sink_location_status=EvidenceState.UNKNOWN,
            flow_trace_status=trace_status,
            sanitizer_patterns_declared=sanitizers,
            sanitizer_declaration_status=declaration_status,
            sanitizer_match_status=EvidenceState.UNKNOWN,
            rules_file_id=rules_file_id,
            rules_file_sha256=rules_sha256,
            observed_json_fields=tuple(observed),
            evidence_provenance=tuple(provenance),
            limitations=tuple(limitations),
        ))
    return tuple(evidence)
