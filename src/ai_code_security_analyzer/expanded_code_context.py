"""Explicit, bounded same-function context selection for JS and TypeScript.

This module only prepares internal evidence. It does not enable LLM calls or
change the default Phase 2A extraction policy.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript

from ai_code_security_analyzer.code_context import (
    CodeContext,
    ContextStatus,
    UntrustedCodeLine,
    read_regular_file_under_root,
    _restricted,
    _safe_parts,
    _sanitize_line,
    _target_id,
    extract_code_context,
)
from ai_code_security_analyzer.models import Finding


MAX_EXPANDED_LINES = 40
MAX_EXPANDED_BYTES = 12_288
MAX_FILE_BYTES = 1_000_000
MAX_LINE_BYTES = 2_048

_GRAMMARS = {
    ".js": (tree_sitter_javascript.language, "javascript"),
    ".jsx": (tree_sitter_javascript.language, "javascript+jsx"),
    ".mjs": (tree_sitter_javascript.language, "javascript"),
    ".cjs": (tree_sitter_javascript.language, "javascript"),
    ".ts": (tree_sitter_typescript.language_typescript, "typescript"),
    ".tsx": (tree_sitter_typescript.language_tsx, "tsx"),
}
_FUNCTION_NODES = {
    "function_declaration", "function_expression", "arrow_function",
    "generator_function", "generator_function_declaration", "method_definition",
}
_CONDITION_NODES = {"if_statement", "switch_statement", "ternary_expression", "conditional_expression"}
_DECLARATION_NODES = {"variable_declarator"}


class IncludedLineRange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    start_line: int = Field(ge=1, strict=True)
    end_line: int = Field(ge=1, strict=True)
    reasons: tuple[str, ...]


class ExpandedContextMetadata(BaseModel):
    """Source-free extraction provenance; never includes code text."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    finding_id: str
    target_id: str
    file_path: str
    included_ranges: tuple[IncludedLineRange, ...]
    status: ContextStatus
    parser: str | None = None
    fallback_reason: str | None = None
    omitted_scopes: tuple[str, ...] = ()
    unresolved_dependencies: tuple[str, ...] = (
        "external_function_bodies_not_inspected",
        "other_files_not_inspected",
    )
    source_flow_verified: Literal[False] = False
    data_flow_analysis_performed: Literal[False] = False
    source_snapshot_sha256: str = Field(repr=False)


@dataclass(frozen=True, slots=True)
class InternalExpandedCodeContext:
    """Sanitized sparse lines plus a Phase 2A-compatible bounded view."""

    metadata: CodeContext
    selection: ExpandedContextMetadata
    lines: tuple[UntrustedCodeLine, ...] = field(default=(), repr=False)
    trust_label: Literal["untrusted_source_code"] = "untrusted_source_code"

    def public_report(self) -> dict[str, object]:
        # Both contracts are metadata-only. No source line is serializable here.
        return {"context": self.metadata.model_dump(mode="json"),
                "selection": self.selection.model_dump(mode="json", exclude={"source_snapshot_sha256"})}


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    reason: str


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _ranges(lines: list[int], reasons: dict[int, set[str]]) -> tuple[IncludedLineRange, ...]:
    result: list[IncludedLineRange] = []
    for number in sorted(lines):
        why = tuple(sorted(reasons.get(number, {"syntax_scope"})))
        if result and number == result[-1].end_line + 1 and why == result[-1].reasons:
            previous = result[-1]
            result[-1] = IncludedLineRange(start_line=previous.start_line, end_line=number, reasons=why)
        else:
            result.append(IncludedLineRange(start_line=number, end_line=number, reasons=why))
    return tuple(result)


def _unavailable(finding: Finding, root: Path, issue: str) -> InternalExpandedCodeContext:
    base = extract_code_context(root, finding)
    metadata = base.metadata.model_copy(update={
        "status": ContextStatus.UNAVAILABLE, "start_line": None, "end_line": None,
        "redacted": issue == "redaction_uncertain", "truncated": False,
        "omitted": True, "issues": (issue,),
    })
    selection = ExpandedContextMetadata(
        finding_id=finding.finding_id, target_id=metadata.target_id,
        file_path=metadata.file_path, included_ranges=(), status=ContextStatus.UNAVAILABLE,
        fallback_reason=issue, omitted_scopes=("source_scope_unavailable",),
        source_snapshot_sha256="0" * 64,
    )
    return InternalExpandedCodeContext(metadata, selection)


def _parse_language(path: str) -> tuple[Language, str] | None:
    extension = Path(path).suffix.lower()
    grammar = _GRAMMARS.get(extension)
    if grammar is None:
        return None
    language_factory, parser_name = grammar
    return Language(language_factory()), parser_name


def _selection_candidates(function, sink, finding_start: int, finding_end: int, source: bytes) -> list[_Candidate]:
    candidates = [_Candidate(finding_start, finding_end, "finding_location")]
    identifiers: set[bytes] = set()
    if sink is not None:
        candidates.append(_Candidate(sink.start_point.row + 1, sink.end_point.row + 1, "risk_call_candidate"))
        for node in _walk(sink):
            if node.type in {"identifier", "property_identifier", "shorthand_property_identifier"}:
                identifiers.add(source[node.start_byte:node.end_byte])
    # These are lexical name matches only. They do not prove reaching definitions,
    # aliasing, dominance, sanitization, or a source-to-sink flow.
    for node in _walk(function):
        if node.type in _DECLARATION_NODES:
            name = node.child_by_field_name("name")
            if name is not None and source[name.start_byte:name.end_byte] in identifiers:
                candidates.append(_Candidate(node.start_point.row + 1, node.end_point.row + 1,
                                             "candidate_variable_name_match"))
        elif node.type in _CONDITION_NODES:
            names = {
                source[item.start_byte:item.end_byte] for item in _walk(node)
                if item.type in {"identifier", "property_identifier"}
            }
            if identifiers.intersection(names):
                candidates.append(_Candidate(node.start_point.row + 1, node.end_point.row + 1,
                                             "candidate_condition_name_match"))
    # A small function header helps orient selected statements if a large body
    # must be represented by sparse ranges.
    candidates.append(_Candidate(function.start_point.row + 1,
                                 min(function.start_point.row + 2, function.end_point.row) + 1,
                                 "containing_function_header"))
    return candidates


def extract_expanded_code_context(
    target_root: Path,
    finding: Finding,
    *,
    end_line: int | None = None,
) -> InternalExpandedCodeContext:
    """Extract an explicitly expanded, same-file context under fixed hard caps.

    If parsing or function discovery is uncertain, return the unchanged bounded
    Phase 2A window and record why expansion was not used.
    """
    try:
        root = target_root.resolve(strict=True)
        if not root.is_dir():
            return _unavailable(finding, target_root, "invalid_root")
    except (OSError, ValueError, RuntimeError):
        return _unavailable(finding, target_root, "invalid_root")
    target_id = _target_id(root)
    parts = _safe_parts(finding.file_path)
    if parts is None:
        return _unavailable(finding, root, "invalid_relative_path")
    if _restricted(parts):
        return _unavailable(finding, root, "restricted_path")
    if finding.line_number is None:
        return _unavailable(finding, root, "missing_location")
    if end_line is not None and (type(end_line) is not int or end_line < finding.line_number):
        return _unavailable(finding, root, "invalid_span")
    language = _parse_language(finding.file_path)
    if language is None:
        fallback_reason = "unsupported_language"
    else:
        fallback_reason = None

    data, issue = read_regular_file_under_root(root, parts, MAX_FILE_BYTES)
    if issue is not None or data is None:
        return _unavailable(finding, root, issue or "file_access_denied")
    if b"\x00" in data:
        return _unavailable(finding, root, "binary_file")
    try:
        source_text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _unavailable(finding, root, "unsupported_encoding")
    source_lines = source_text.split("\n") if source_text else []
    if source_text.endswith("\n"):
        source_lines.pop()
    source_lines = [line.removesuffix("\r") for line in source_lines]
    finding_end = end_line or finding.line_number
    if finding_end > len(source_lines):
        return _unavailable(finding, root, "location_out_of_range")
    if finding_end - finding.line_number + 1 > MAX_EXPANDED_LINES:
        return _unavailable(finding, root, "finding_span_too_large")

    source_hash = hashlib.sha256(data).hexdigest()
    selected_reasons: dict[int, set[str]] = {}
    parser_name: str | None = None
    omitted_scopes: set[str] = set()
    coverage_truncated = False
    if fallback_reason is None:
        assert language is not None
        parser_language, parser_name = language
        try:
            parser = Parser(parser_language)
            tree = parser.parse(data)
        except Exception:
            tree = None
        if tree is None or tree.root_node.has_error:
            fallback_reason = "parse_error"
        else:
            first_row, last_row = finding.line_number - 1, finding_end - 1
            function = None
            for node in _walk(tree.root_node):
                if node.type in _FUNCTION_NODES and node.start_point.row <= first_row <= node.end_point.row:
                    if last_row <= node.end_point.row and (function is None or node.end_byte - node.start_byte < function.end_byte - function.start_byte):
                        function = node
            if function is None:
                fallback_reason = "function_scope_not_found"
            else:
                sink_nodes = [node for node in _walk(function)
                              if node.type == "call_expression"
                              and node.start_point.row <= last_row
                              and node.end_point.row >= first_row]
                sink = min(sink_nodes, key=lambda node: node.end_byte - node.start_byte) if sink_nodes else None
                function_lines = list(range(function.start_point.row + 1, function.end_point.row + 2))
                function_bytes = sum(len(source_lines[number - 1].encode("utf-8")) + 1
                                     for number in function_lines if number <= len(source_lines))
                if len(function_lines) <= MAX_EXPANDED_LINES and function_bytes <= MAX_EXPANDED_BYTES:
                    for number in function_lines:
                        selected_reasons[number] = {"containing_function"}
                    for candidate in _selection_candidates(function, sink, finding.line_number,
                                                           finding_end, data):
                        for number in range(candidate.start, candidate.end + 1):
                            if number in selected_reasons:
                                selected_reasons[number].add(candidate.reason)
                else:
                    coverage_truncated = True
                    omitted_scopes.update({"function_scope_partially_selected", "control_flow_not_analyzed"})
                    candidates = _selection_candidates(function, sink, finding.line_number,
                                                       finding_end, data)
                    line_budget = MAX_EXPANDED_LINES
                    byte_budget = MAX_EXPANDED_BYTES
                    for candidate in sorted(candidates, key=lambda item: (
                        0 if item.reason == "finding_location" else 1,
                        0 if item.reason == "risk_call_candidate" else 1,
                        item.start,
                    )):
                        for number in range(candidate.start, candidate.end + 1):
                            if number < 1 or number > len(source_lines):
                                continue
                            if number in selected_reasons:
                                selected_reasons[number].add(candidate.reason)
                                continue
                            cost = len(source_lines[number - 1].encode("utf-8")) + 1
                            if len(selected_reasons) >= line_budget or cost > byte_budget:
                                coverage_truncated = True
                                omitted_scopes.add("selection_limit_reached")
                                continue
                            selected_reasons[number] = {candidate.reason}
                            byte_budget -= cost
                omitted_scopes.update({"external_function_bodies_not_inspected", "other_files_not_inspected",
                                       "cross_file_flow_not_traced", "source_to_sink_flow_not_verified"})

    if fallback_reason is not None:
        fallback_data, fallback_issue = read_regular_file_under_root(root, parts, MAX_FILE_BYTES)
        if (fallback_issue is not None or fallback_data is None
                or hashlib.sha256(fallback_data).hexdigest() != source_hash):
            return _unavailable(finding, root, "file_changed_between_reads")
        base = extract_code_context(root, finding, end_line=end_line)
        if any(
            line.number > len(source_lines)
            or (
                "[line omitted: length limit]"
                if len(source_lines[line.number - 1].encode("utf-8")) > MAX_LINE_BYTES
                and not finding.line_number <= line.number <= finding_end
                else _sanitize_line(source_lines[line.number - 1])[0]
            ) != line.text
            for line in base.lines
        ):
            return _unavailable(finding, root, "file_changed_between_reads")
        selected_reasons = {line.number: {"phase2a_fallback_window"} for line in base.lines}
        omitted_scopes.add("expanded_scope_not_collected")
        base_metadata = base.metadata
        status = base_metadata.status
        lines = base.lines
        parser_name = None
    else:
        ordered_numbers = sorted(selected_reasons)
        sanitized: list[UntrustedCodeLine] = []
        redacted = False
        truncated = coverage_truncated
        total_bytes = 0
        for number in ordered_numbers:
            text = source_lines[number - 1]
            if len(text.encode("utf-8")) > MAX_LINE_BYTES:
                if finding.line_number <= number <= finding_end:
                    return _unavailable(finding, root, "finding_line_too_long")
                text = "[line omitted: length limit]"
                truncated = True
                coverage_truncated = True
                omitted_scopes.add("long_line_omitted")
            safe, changed = _sanitize_line(text)
            if safe is None:
                return _unavailable(finding, root, "redaction_uncertain")
            redacted |= changed
            cost = len(safe.encode("utf-8")) + 1
            if total_bytes + cost > MAX_EXPANDED_BYTES:
                if finding.line_number <= number <= finding_end:
                    return _unavailable(finding, root, "finding_exceeds_context_byte_limit")
                selected_reasons.pop(number, None)
                truncated = True
                coverage_truncated = True
                omitted_scopes.add("byte_limit_omitted_lines")
                continue
            total_bytes += cost
            sanitized.append(UntrustedCodeLine(number, safe))
        lines = tuple(sanitized)
        if not lines or not any(line.number == finding.line_number for line in lines):
            return _unavailable(finding, root, "finding_location_not_selected")
        first, last = lines[0].number, lines[-1].number
        status = ContextStatus.TRUNCATED if truncated else (ContextStatus.REDACTED if redacted else ContextStatus.AVAILABLE)
        base_metadata = CodeContext(
            finding_id=finding.finding_id, target_id=target_id, file_path=finding.file_path,
            rule_id=finding.rule_id, finding_line=finding.line_number,
            finding_end_line=finding_end, start_line=first, end_line=last,
            status=status, redacted=redacted, truncated=truncated,
            omitted=first > 1 or last < len(source_lines) or bool(omitted_scopes),
            issues=((fallback_reason,) if fallback_reason else ()) + (("context_truncated",) if truncated else ()),
        )

    actual_lines = [line.number for line in lines]
    selected_range_records = _ranges(actual_lines, selected_reasons)
    selection = ExpandedContextMetadata(
        finding_id=finding.finding_id, target_id=target_id,
        file_path=base_metadata.file_path, included_ranges=selected_range_records,
        status=status, parser=parser_name, fallback_reason=fallback_reason,
        omitted_scopes=tuple(sorted(omitted_scopes)),
        source_snapshot_sha256=source_hash,
    )
    return InternalExpandedCodeContext(base_metadata, selection, tuple(lines))
