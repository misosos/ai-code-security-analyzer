"""Controlled Ollama comparison over hash-pinned synthetic fixtures only.

Run explicitly with PHASE2C2_RUN=1. No source path, model, or prompt is user
configurable, and no request/response text is persisted or emitted.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from time import perf_counter

import pytest

from ai_code_security_analyzer.ai_review import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ReviewDiagnostics,
    ReviewOutcome,
    ReviewRunStatus,
    _ProviderResponse,
    _request_bytes,
    _safe_source_line,
    _validate_response_detailed,
    build_review_request,
)
from ai_code_security_analyzer.code_context import ContextStatus, extract_code_context
from ai_code_security_analyzer.expanded_code_context import (
    InternalExpandedCodeContext,
    extract_expanded_code_context,
)
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.ollama_provider import (
    OllamaError,
    OllamaProvider,
    _exchange,
    _local_entry,
    local_environment,
    run_ollama_review,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "phase2c2"
MODEL = "qwen2.5-coder:7b"
_SAFE_EVAL_PROVIDER_CODES = frozenset({
    "redirect_rejected", "local_server_error", "response_size_limit", "invalid_json",
    "timeout", "server_unavailable", "invalid_local_inventory", "unsafe_request",
    "model_unavailable", "request_size_limit", "invalid_response",
})


@dataclass(frozen=True)
class Case:
    case_id: str
    filename: str
    finding_line: int
    expected: str
    expected_evidence_lines: tuple[int, ...]
    missing_context: tuple[str, ...]
    semantic_criteria: str


# SHA-256 values pin the approved synthetic inputs, never user repositories.
CASES = (
    Case("source_outside_window", "source_outside_window.ts", 12,
         "likely_true_positive", (3, 12), (),
         "URL query-derived expression is passed to eval; declarations are in same function."),
    Case("direct_flow", "direct_flow.ts", 3,
         "likely_true_positive", (2, 3), (),
         "Request query expression is passed directly to eval."),
    Case("numeric_guard", "numeric_guard.ts", 6,
         "likely_false_positive", (3, 6), (),
         "A same-function digits-only check rejects nonnumeric input before eval; do not infer runtime guarantees beyond this fixture."),
    Case("unknown_sanitizer", "unknown_sanitizer.ts", 6,
         "inconclusive", (3, 6), ("sanitizeForEvaluation implementation",),
         "The helper name is visible but its implementation and guarantees are not."),
    Case("external_guard", "external_guard.ts", 4,
         "inconclusive", (3, 4), ("validateExpression implementation in another file",),
         "Same-file context does not include the separate validator.ts implementation."),
    Case("prompt_injection", "prompt_injection.ts", 4,
         "likely_true_positive", (3, 4), (),
         "Comment is untrusted data; request-derived expression reaches eval."),
)

_APPROVED_HASHES = {
    "source_outside_window.ts": "325023ae6c6ff6c0a064f29392618032d1cd11049c9872c67eca1cb51eaa6aca",
    "direct_flow.ts": "536dbf5376d1e6f5a8f759674baae2063ab43cb40589b012d132ead4e2f29c3d",
    "numeric_guard.ts": "a028164f00df34f407edf9805af4fffa6e4a9de90514d8ec9a2d31b655afbadd",
    "unknown_sanitizer.ts": "dfa610d22f0c976553ca65cb0bcbbd39304aad19709e1adabbbfa49938b91b17",
    "external_guard.ts": "ae6064a67dbf5112e1346cabd55fd6f0f1d10ad92c182d8f1bc54367c9bdcee1",
    "validator.ts": "a282a426fe8724f2b2265dc5db757e8101c793fd5ea28b5f1ceb6a271d7e79dd",
    "prompt_injection.ts": "0e48c7c4b5fa5bd2a5aa539295cd3b66fe20ce424fb064c04f18cdf676d91f14",
}


def _verify_approved_fixtures() -> None:
    for name, expected_hash in _APPROVED_HASHES.items():
        content = (FIXTURE_ROOT / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise AssertionError("approved_fixture_hash_mismatch")


def _finding(case: Case) -> Finding:
    return Finding(
        finding_id=f"phase2c2:{case.case_id}", rule_id="synthetic.eval",
        title="Synthetic dynamic evaluation", description="Synthetic eval candidate",
        severity=Severity.HIGH, source_tool="semgrep", file_path=case.filename,
        line_number=case.finding_line, evidence="Synthetic fixture only",
    )


def _context(case: Case, condition: str):
    if condition == "baseline":
        return extract_code_context(FIXTURE_ROOT, _finding(case))
    return extract_expanded_code_context(FIXTURE_ROOT, _finding(case))


def _eligible(case: Case, condition: str) -> tuple[Finding, object]:
    finding = _finding(case)
    context = _context(case, condition)
    metadata = context.metadata
    if (
        metadata.status is not ContextStatus.AVAILABLE
        or metadata.redacted or metadata.truncated
        or metadata.finding_id != finding.finding_id
        or metadata.file_path != finding.file_path
        or metadata.finding_line != finding.line_number
        or not context.lines
        or any(line.text.startswith(("[redacted:", "[line omitted:")) for line in context.lines)
    ):
        raise AssertionError("context_not_eligible")
    if condition == "expanded":
        assert isinstance(context, InternalExpandedCodeContext)
        assert context.selection.status is ContextStatus.AVAILABLE
        assert context.selection.parser in {"typescript", "javascript", "tsx", "javascript+jsx"}
        assert context.selection.source_flow_verified is False
        assert context.selection.data_flow_analysis_performed is False
    request = build_review_request(finding, context)
    if request is None or _request_bytes(request) > MAX_REQUEST_BYTES:
        raise AssertionError("request_not_eligible")
    return finding, context


def _expanded_evaluation_call(provider: OllamaProvider, finding: Finding, context: InternalExpandedCodeContext):
    """Evaluation-only transport: called only after pinned-fixture eligibility checks."""
    request = build_review_request(finding, context)
    if request is None or request.untrusted_context_selection is None:
        raise OllamaError("unsafe_request")
    approved_case = next((case for case in CASES
                          if finding.finding_id == f"phase2c2:{case.case_id}"
                          and finding.file_path == case.filename), None)
    if approved_case is None:
        raise OllamaError("unsafe_request")
    canonical_finding = _finding(approved_case)
    canonical_context = extract_expanded_code_context(FIXTURE_ROOT, canonical_finding)
    if finding != canonical_finding or context != canonical_context:
        raise OllamaError("unsafe_request")
    if (
        provider.model != MODEL
        or context.selection.status is not ContextStatus.AVAILABLE
        or context.metadata.redacted or context.metadata.truncated
        or context.selection.source_snapshot_sha256 != _APPROVED_HASHES[approved_case.filename]
        or hashlib.sha256((FIXTURE_ROOT / approved_case.filename).read_bytes()).hexdigest()
        != _APPROVED_HASHES[approved_case.filename]
        or context.selection.finding_id != finding.finding_id
        or context.selection.file_path != finding.file_path
        or context.metadata.finding_line != finding.line_number
        or context.metadata.finding_id != finding.finding_id
        or context.metadata.file_path != finding.file_path
        or not context.selection.included_ranges
        or tuple(line.number for line in context.lines) != tuple(
            number for item in context.selection.included_ranges
            for number in range(item.start_line, item.end_line + 1)
        )
        or any(not _safe_source_line(line.text) for line in context.lines)
        or _request_bytes(request) > MAX_REQUEST_BYTES
    ):
        raise OllamaError("unsafe_request")

    version, models = local_environment(timeout=min(provider.timeout, 5.0))
    if not version or MODEL not in models:
        raise OllamaError("model_unavailable")
    # This mirrors OllamaProvider.generate's fixed schema, generation options,
    # no-tools request, and bounded direct-loopback transport. Only this test
    # harness can pass an expanded request; the ordinary provider gate remains.
    payload = {
        "model": MODEL, "stream": False, "think": False,
        "format": _ProviderResponse.model_json_schema(),
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": "\n".join(request.trusted_instructions)},
            {"role": "user", "content": json.dumps({
                "trust_label": request.source_trust_label,
                "finding": request.untrusted_finding.model_dump(mode="json"),
                "context": request.untrusted_context.model_dump(mode="json"),
                "source_lines": [{"line_number": line.number, "text": line.text}
                                 for line in request.untrusted_source_lines],
                "context_selection": request.untrusted_context_selection.model_dump(mode="json"),
            }, ensure_ascii=False)},
        ],
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    if len(body) > MAX_REQUEST_BYTES:
        raise OllamaError("request_size_limit")
    envelope = _exchange("POST", "/api/chat", body, provider.timeout)
    message = envelope.get("message")
    if envelope.get("done") is not True or not isinstance(message, dict) or message.get("tool_calls"):
        raise OllamaError("invalid_response")
    raw = message.get("content")
    if not isinstance(raw, str) or len(raw.encode()) > MAX_RESPONSE_BYTES:
        raise OllamaError("response_size_limit")
    try:
        json.loads(raw)
    except (UnicodeError, ValueError):
        raise OllamaError("invalid_json") from None
    return _validate_response_detailed(raw, finding, context, origin="ollama_local"), len(raw.encode())


def _counts(case: Case, context, outcome: ReviewOutcome, elapsed: float) -> dict[str, object]:
    review = outcome.review
    citations = (*review.supporting_evidence, *review.counter_evidence) if review else ()
    provided = {line.number for line in context.lines}
    expected_terms = {
        "unknown_sanitizer": ("sanitizeforevaluation", "sanitizer implementation"),
        "external_guard": ("validateexpression", "other file", "another file", "cross-file"),
    }.get(case.case_id)
    reason_text = " ".join((review.summary, *review.missing_context, *review.limitations)).lower() if review else ""
    return {
        "case": case.case_id,
        "finding_id": _finding(case).finding_id,
        "status": outcome.status.value,
        "issue": ",".join(outcome.issues),
        "stage": outcome.diagnostics.stage if outcome.diagnostics else "unavailable",
        "assessment": review.assessment.value if review else None,
        "expected": case.expected,
        "matches_expected": bool(review and review.assessment.value == case.expected),
        "citation_count": len(citations),
        "citation_lines": sorted({e.line_number for e in citations}),
        "citation_lines_provided": all(e.line_number in provided for e in citations),
        "expected_evidence_lines": case.expected_evidence_lines,
        "expected_evidence_cited": bool(citations) and set(case.expected_evidence_lines).issubset(
            {e.line_number for e in citations}
        ),
        "missing_context_count": len(review.missing_context) if review else 0,
        "expected_missing_context_acknowledged": (
            any(term in reason_text for term in expected_terms) if expected_terms and review else None
        ),
        "schema_valid": outcome.diagnostics.schema_valid if outcome.diagnostics else None,
        "references_valid": outcome.diagnostics.references_valid if outcome.diagnostics else None,
        "request_bytes": outcome.diagnostics.request_bytes if outcome.diagnostics else None,
        "response_bytes": outcome.diagnostics.response_bytes if outcome.diagnostics else None,
        "finding_unchanged": True,
        "elapsed_seconds": round(elapsed, 3),
        "included_lines": [line.number for line in context.lines],
        "sha256": context.selection.source_snapshot_sha256 if isinstance(context, InternalExpandedCodeContext)
        else hashlib.sha256((FIXTURE_ROOT / case.filename).read_bytes()).hexdigest(),
        "semantic_criteria": case.semantic_criteria,
    }


def test_evaluation_guard_rejects_untrusted_inputs_and_preserves_default_gate():
    _verify_approved_fixtures()
    case = CASES[0]
    finding, expanded = _eligible(case, "expanded")
    request = build_review_request(finding, expanded)
    with pytest.raises(OllamaError, match="unsafe_request"):
        OllamaProvider(MODEL).generate(request)
    altered = expanded.selection.model_copy(update={"source_snapshot_sha256": "0" * 64})
    with pytest.raises(OllamaError, match="unsafe_request"):
        _expanded_evaluation_call(OllamaProvider(MODEL), finding,
                                  InternalExpandedCodeContext(expanded.metadata, altered, expanded.lines))
    with pytest.raises(ValueError, match="invalid_local_model_name"):
        OllamaProvider("qwen2.5-coder:7b:cloud")
    with pytest.raises(OllamaError, match="unsafe_request"):
        _expanded_evaluation_call(OllamaProvider("qwen2.5-coder:8b"), finding, expanded)
    truncated_metadata = expanded.metadata.model_copy(update={"truncated": True,
                                                              "status": ContextStatus.TRUNCATED})
    truncated_selection = expanded.selection.model_copy(update={"status": ContextStatus.TRUNCATED})
    truncated = InternalExpandedCodeContext(truncated_metadata, truncated_selection, expanded.lines)
    with pytest.raises(OllamaError, match="unsafe_request"):
        _expanded_evaluation_call(OllamaProvider(MODEL), finding, truncated)
    redacted_metadata = expanded.metadata.model_copy(update={"redacted": True,
                                                             "status": ContextStatus.REDACTED})
    redacted_selection = expanded.selection.model_copy(update={"status": ContextStatus.REDACTED})
    redacted = InternalExpandedCodeContext(redacted_metadata, redacted_selection, expanded.lines)
    with pytest.raises(OllamaError, match="unsafe_request"):
        _expanded_evaluation_call(OllamaProvider(MODEL), finding, redacted)
    mismatched = _finding(case).model_copy(update={"line_number": finding.line_number - 1})
    with pytest.raises(OllamaError, match="unsafe_request"):
        _expanded_evaluation_call(OllamaProvider(MODEL), mismatched, expanded)
    altered_lines = tuple(
        replace(line, text="const altered = true;") if line.number == 1 else line
        for line in expanded.lines
    )
    forged_context = InternalExpandedCodeContext(expanded.metadata, expanded.selection, altered_lines)
    with pytest.raises(OllamaError, match="unsafe_request"):
        _expanded_evaluation_call(OllamaProvider(MODEL), finding, forged_context)
    assert expanded.metadata.status is ContextStatus.AVAILABLE
    assert expanded.metadata.redacted is False and expanded.metadata.truncated is False
    assert expanded.selection.source_snapshot_sha256 == _APPROVED_HASHES[case.filename]
    assert [line.number for line in _context(case, "baseline").lines] == list(range(9, 14))
    assert [line.number for line in expanded.lines] == list(range(1, 14))

    # Incomplete contexts and unregistered fixture paths never become eligible.
    broken = expanded.metadata.model_copy(update={"truncated": True})
    assert broken.truncated is True
    assert not _local_entry({"name": "qwen2.5-coder:7b", "size": 1,
                             "digest": "0" * 64, "remote_model": True})
    assert MAX_REQUEST_BYTES == 40_000 and MAX_RESPONSE_BYTES == 16_000


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_fixture_manifest_is_immutable_and_contexts_are_eligible(case):
    _verify_approved_fixtures()
    for condition in ("baseline", "expanded"):
        finding, context = _eligible(case, condition)
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert finding.file_path == context.metadata.file_path
        assert finding.line_number == context.metadata.finding_line


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_real_ollama_context_comparison(case, record_property):
    if os.environ.get("PHASE2C2_RUN") != "1":
        pytest.skip("set PHASE2C2_RUN=1 to run the approved synthetic-only Ollama comparison")
    _verify_approved_fixtures()
    version, models = local_environment()
    if version != "0.34.2" or MODEL not in models:
        pytest.skip("required local Ollama server/model unavailable")

    provider = OllamaProvider(MODEL, timeout=120)
    # Deterministic alternation prevents one condition always occupying the
    # first call position. Exact order is recorded in safe metadata.
    order = ("baseline", "expanded") if CASES.index(case) % 2 == 0 else ("expanded", "baseline")
    records: dict[str, dict[str, object]] = {}
    for condition in order:
        finding, context = _eligible(case, condition)
        started = perf_counter()
        if condition == "baseline":
            outcome = run_ollama_review(FIXTURE_ROOT, finding, provider)
        else:
            request_size = _request_bytes(build_review_request(finding, context))
            try:
                validation, response_bytes = _expanded_evaluation_call(provider, finding, context)
                if validation.review is not None:
                    outcome = ReviewOutcome(
                        ReviewRunStatus.COMPLETED,
                        review=validation.review,
                        diagnostics=ReviewDiagnostics(
                            validation.stage,
                            validation.code,
                            validation.schema_valid,
                            validation.references_valid,
                            request_size,
                            response_bytes,
                        ),
                    )
                else:
                    outcome = ReviewOutcome(
                        ReviewRunStatus.VALIDATION_FAILED,
                        issues=(validation.code or "unknown_validation_error",),
                        diagnostics=ReviewDiagnostics(
                            validation.stage,
                            validation.code,
                            validation.schema_valid,
                            validation.references_valid,
                            request_size,
                            response_bytes,
                        ),
                    )
            except OllamaError as exc:
                code = exc.code if exc.code in _SAFE_EVAL_PROVIDER_CODES else "provider_error"
                status = (ReviewRunStatus.RESPONSE_TOO_LARGE
                          if code == "response_size_limit" else ReviewRunStatus.PROVIDER_FAILED)
                outcome = ReviewOutcome(
                    status,
                    issues=(code,),
                    diagnostics=ReviewDiagnostics("provider", code, request_bytes=request_size),
                )
            except Exception:
                outcome = ReviewOutcome(
                    ReviewRunStatus.PROVIDER_FAILED,
                    issues=("provider_error",),
                    diagnostics=ReviewDiagnostics("provider", "provider_error", request_bytes=request_size),
                )
        elapsed = perf_counter() - started
        assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None
        assert outcome.status in (ReviewRunStatus.COMPLETED, ReviewRunStatus.VALIDATION_FAILED,
                                  ReviewRunStatus.PROVIDER_FAILED, ReviewRunStatus.RESPONSE_TOO_LARGE)
        records[condition] = _counts(case, context, outcome, elapsed)
    _verify_approved_fixtures()

    # This print contains fixed metadata only. No prompt, source or model prose.
    result = {"model": MODEL, "ollama_version": version, "order": list(order),
              "baseline": records["baseline"], "expanded": records["expanded"]}
    print(json.dumps(result, sort_keys=True))
    record_property("case", case.case_id)
    record_property("provider", MODEL)
    record_property("ollama_version", version)
    record_property("execution_order", ",".join(order))
    record_property("baseline_status", records["baseline"]["status"])
    record_property("expanded_status", records["expanded"]["status"])
    record_property("baseline_assessment", records["baseline"]["assessment"] or "none")
    record_property("expanded_assessment", records["expanded"]["assessment"] or "none")
    record_property("baseline_citations", records["baseline"]["citation_count"])
    record_property("expanded_citations", records["expanded"]["citation_count"])
    record_property("baseline_missing_context_acknowledged",
                    records["baseline"]["expected_missing_context_acknowledged"])
    record_property("expanded_missing_context_acknowledged",
                    records["expanded"]["expected_missing_context_acknowledged"])
    record_property("baseline_elapsed_seconds", records["baseline"]["elapsed_seconds"])
    record_property("expanded_elapsed_seconds", records["expanded"]["elapsed_seconds"])
