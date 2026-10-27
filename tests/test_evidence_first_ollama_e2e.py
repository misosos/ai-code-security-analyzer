"""Explicit Ollama PoC over pinned synthetic fixtures; never user repositories."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

import pytest

from ai_code_security_analyzer.ai_review import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ReviewOutcome,
    ReviewRunStatus,
    _request_bytes,
    build_review_request,
)
from ai_code_security_analyzer.code_context import ContextStatus, extract_code_context
from ai_code_security_analyzer.evidence_candidates import (
    CandidateKind,
    EvidenceCandidateBundle,
    EvidenceFirstReview,
    build_evidence_candidates,
    build_evidence_first_request,
    evidence_first_request_bytes,
    evidence_first_response_schema,
    validate_candidate_bundle,
    validate_evidence_first_response,
)
from ai_code_security_analyzer.expanded_code_context import extract_expanded_code_context
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.ollama_provider import (
    OllamaError,
    OllamaProvider,
    _exchange,
    local_environment,
    run_ollama_review,
)


MODEL = "qwen2.5-coder:7b"
FIXTURE_DIRS = {
    "phase2c2": Path(__file__).parent / "fixtures" / "phase2c2",
    "phase2d1": Path(__file__).parent / "fixtures" / "phase2d1",
}
_HASHES = {
    ("phase2c2", "direct_flow.ts"): "536dbf5376d1e6f5a8f759674baae2063ab43cb40589b012d132ead4e2f29c3d",
    ("phase2c2", "external_guard.ts"): "ae6064a67dbf5112e1346cabd55fd6f0f1d10ad92c182d8f1bc54367c9bdcee1",
    ("phase2c2", "prompt_injection.ts"): "0e48c7c4b5fa5bd2a5aa539295cd3b66fe20ce424fb064c04f18cdf676d91f14",
    ("phase2d1", "numeric_guard_compact.ts"): "620f6751ab9084f58bf488ffe1ea9774c6a5196c2c17c32076ff1beae8f1fb70",
}


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    fixture_group: str
    filename: str
    finding_line: int
    expected: str
    relevant_candidates: tuple[tuple[str, int], ...]
    missing_context: tuple[str, ...] = ()


CASES = (
    EvaluationCase("direct_flow", "phase2c2", "direct_flow.ts", 3,
                   "likely_true_positive", (("call_expression", 3), ("variable_declaration", 2))),
    EvaluationCase("numeric_guard_compact", "phase2d1", "numeric_guard_compact.ts", 3,
                   "likely_false_positive", (("conditional_expression", 2),)),
    EvaluationCase("external_guard", "phase2c2", "external_guard.ts", 4,
                   "inconclusive", (), ("validateExpression implementation",)),
    EvaluationCase("prompt_injection", "phase2c2", "prompt_injection.ts", 4,
                   "likely_true_positive", (("call_expression", 4), ("variable_declaration", 3))),
)

_SAFE_PROVIDER_CODES = frozenset({
    "redirect_rejected", "local_server_error", "response_size_limit", "invalid_json",
    "timeout", "server_unavailable", "invalid_local_inventory", "unsafe_request",
    "model_unavailable", "request_size_limit", "invalid_response",
})


def _fixture(case: EvaluationCase) -> Path:
    return FIXTURE_DIRS[case.fixture_group] / case.filename


def _verify_fixtures() -> None:
    for key, expected in _HASHES.items():
        path = FIXTURE_DIRS[key[0]] / key[1]
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise AssertionError("approved_fixture_hash_mismatch")


def _finding(case: EvaluationCase) -> Finding:
    return Finding(
        finding_id=f"phase2d1:{case.case_id}", rule_id="synthetic.eval",
        title="Synthetic dynamic evaluation", description="Synthetic static-analysis candidate",
        severity=Severity.HIGH, source_tool="semgrep", file_path=case.filename,
        line_number=case.finding_line, evidence="Synthetic fixture only",
    )


def _eligible(case: EvaluationCase):
    finding = _finding(case)
    root = FIXTURE_DIRS[case.fixture_group]
    baseline = extract_code_context(root, finding)
    expanded = extract_expanded_code_context(root, finding)
    if (baseline.metadata.status is not ContextStatus.AVAILABLE
            or baseline.metadata.redacted or baseline.metadata.truncated
            or expanded.metadata.status is not ContextStatus.AVAILABLE
            or expanded.metadata.redacted or expanded.metadata.truncated
            or [line.number for line in baseline.lines] != [line.number for line in expanded.lines]
            or tuple(line.text for line in baseline.lines) != tuple(line.text for line in expanded.lines)):
        raise AssertionError("comparison_context_mismatch")
    bundle = build_evidence_candidates(finding, baseline)
    if not validate_candidate_bundle(finding, baseline, bundle):
        raise AssertionError("candidate_bundle_invalid")
    request = build_evidence_first_request(finding, baseline, bundle)
    normal_request = build_review_request(finding, baseline)
    if (request is None or normal_request is None
            or evidence_first_request_bytes(request) > MAX_REQUEST_BYTES
            or _request_bytes(normal_request) > MAX_REQUEST_BYTES
            or hashlib.sha256(_fixture(case).read_bytes()).hexdigest()
            != _HASHES[(case.fixture_group, case.filename)]):
        raise AssertionError("request_not_eligible")
    return finding, baseline, expanded, bundle, request


def _evidence_payload(request) -> dict[str, object]:
    return {
        "model": MODEL,
        "stream": False,
        "think": False,
        "format": evidence_first_response_schema(),
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": "\n".join(request.trusted_instructions)},
            {"role": "user", "content": json.dumps({
                "trust_label": "untrusted_source_code",
                "finding": request.finding.model_dump(mode="json"),
                "context": request.context.model_dump(mode="json"),
                "source_lines": [{"line_number": line.number, "text": line.text}
                                 for line in request.source_lines],
                "source_context_id": request.source_context_id,
                "candidates": [candidate.model_dump(mode="json") for candidate in request.candidates],
            }, ensure_ascii=False)},
        ],
    }


def _run_evidence_first(provider: OllamaProvider, finding: Finding, context, bundle: EvidenceCandidateBundle):
    request = build_evidence_first_request(finding, context, bundle)
    if request is None:
        raise OllamaError("unsafe_request")
    body = json.dumps(_evidence_payload(request), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise OllamaError("request_size_limit")
    version, models = local_environment(timeout=min(provider.timeout, 5.0))
    if version != "0.34.2" or MODEL not in models:
        raise OllamaError("model_unavailable")
    envelope = _exchange("POST", "/api/chat", body, provider.timeout)
    message = envelope.get("message")
    if envelope.get("done") is not True or not isinstance(message, dict) or message.get("tool_calls"):
        raise OllamaError("invalid_response")
    raw = message.get("content")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise OllamaError("response_size_limit")
    try:
        json.loads(raw)
    except (UnicodeError, ValueError):
        raise OllamaError("invalid_json") from None
    result = validate_evidence_first_response(raw, finding, context, bundle)
    return result, len(raw.encode("utf-8")), len(body)


def _safe_evidence_metrics(case: EvaluationCase, bundle: EvidenceCandidateBundle,
                           outcome: EvidenceFirstReview | None, code: str | None,
                           request_size: int | None, response_size: int | None,
                           elapsed: float) -> dict[str, object]:
    candidate_by_id = {candidate.candidate_id: candidate for candidate in bundle.candidates}
    selected = (() if outcome is None else
                (*outcome.supporting_evidence, *outcome.counter_evidence))
    selected_candidates = [candidate_by_id[item.candidate_id] for item in selected
                           if item.candidate_id in candidate_by_id]
    selected_anchors = {(item.candidate_kind.value, line)
                        for item in selected_candidates
                        for line in range(item.start_line, item.end_line + 1)}
    anchor_relevant = (any((kind, line) in selected_anchors for kind, line in case.relevant_candidates)
                       if case.relevant_candidates and selected else None)
    return {
        "case": case.case_id,
        "status": "completed" if outcome else (code or "rejected"),
        "assessment": outcome.assessment.value if outcome else None,
        "expected": case.expected,
        "matches_expected": bool(outcome and outcome.assessment.value == case.expected),
        "candidate_count": len(bundle.candidates),
        "selected_candidate_count": len(selected),
        "selected_candidate_kinds_lines": sorted({(item.candidate_kind.value, item.start_line, item.end_line)
                                                   for item in selected_candidates}),
        "all_selected_ids_structurally_valid": (
            outcome.candidate_ids_structurally_valid if outcome else None
        ),
        "candidate_anchor_relevant": anchor_relevant,
        "semantic_claims_verified": False,
        "missing_context_count": len(outcome.missing_context) if outcome else 0,
        "schema_valid": (
            None if code in {"timeout", "server_unavailable", "local_server_error"}
            else outcome is not None if code is None
            else code not in {"invalid_json", "schema_validation_failed", "unexpected_response_field"}
        ),
        "request_bytes": request_size,
        "response_bytes": response_size,
        "elapsed_seconds": round(elapsed, 3),
    }


def test_evaluation_uses_identical_code_context_and_candidate_manifest():
    _verify_fixtures()
    for case in CASES:
        finding, baseline, expanded, bundle, request = _eligible(case)
        assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None
        assert [line.number for line in baseline.lines] == [line.number for line in expanded.lines]
        assert bundle.included_line_numbers == tuple(line.number for line in baseline.lines)
        assert request.source_context_id == bundle.source_context_id
        assert len(bundle.candidates) <= 24


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_real_model_evidence_first_pair(case, record_property):
    if os.environ.get("PHASE2D1_RUN") != "1":
        pytest.skip("set PHASE2D1_RUN=1 for the approved synthetic-only Ollama evaluation")
    _verify_fixtures()
    version, models = local_environment()
    if version != "0.34.2" or MODEL not in models:
        pytest.skip("required local Ollama server/model unavailable")

    finding, context, _expanded, bundle, _request = _eligible(case)
    provider = OllamaProvider(MODEL, timeout=120)
    order = ("baseline", "evidence_first") if CASES.index(case) % 2 == 0 else ("evidence_first", "baseline")
    results: dict[str, dict[str, object]] = {}
    for condition in order:
        started = perf_counter()
        if condition == "baseline":
            legacy = run_ollama_review(FIXTURE_DIRS[case.fixture_group], finding, provider)
            review = legacy.review
            result = _safe_evidence_metrics(
                case, bundle, None, legacy.issues[0] if not review and legacy.issues else None,
                legacy.diagnostics.request_bytes if legacy.diagnostics else None,
                legacy.diagnostics.response_bytes if legacy.diagnostics else None,
                perf_counter() - started,
            )
            result.update({"status": legacy.status.value,
                           "assessment": review.assessment.value if review else None,
                           "selected_candidate_count": 0,
                           "all_selected_ids_structurally_valid": None,
                           "candidate_anchor_relevant": None,
                           "matches_expected": bool(review and review.assessment.value == case.expected)})
        else:
            try:
                validation, response_size, request_size = _run_evidence_first(provider, finding, context, bundle)
                result = _safe_evidence_metrics(
                    case, bundle, validation.review, validation.code,
                    request_size, response_size, perf_counter() - started,
                )
                result.update({"status": "completed" if validation.review else validation.code,
                               "schema_valid": validation.schema_valid,
                               "references_valid": validation.references_valid})
            except OllamaError as exc:
                code = exc.code if exc.code in _SAFE_PROVIDER_CODES else "provider_error"
                result = _safe_evidence_metrics(case, bundle, None, code, None, None,
                                                perf_counter() - started)
            except Exception:
                result = _safe_evidence_metrics(case, bundle, None, "provider_error", None, None,
                                                perf_counter() - started)
        assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None
        results[condition] = result
    _verify_fixtures()
    print(json.dumps({"model": MODEL, "ollama_version": version, "order": order,
                      "baseline": results["baseline"], "evidence_first": results["evidence_first"]},
                     sort_keys=True))
    record_property("case", case.case_id)
    record_property("model", MODEL)
    record_property("ollama_version", version)
    record_property("order", ",".join(order))
    record_property("baseline_assessment", results["baseline"]["assessment"] or "none")
    record_property("evidence_first_assessment", results["evidence_first"]["assessment"] or "none")
    record_property("candidate_count", results["evidence_first"]["candidate_count"])
    record_property("selected_candidate_count", results["evidence_first"]["selected_candidate_count"])
    record_property("candidate_anchor_relevant", results["evidence_first"]["candidate_anchor_relevant"])
    record_property("evidence_first_status", results["evidence_first"]["status"])
    record_property("evidence_first_elapsed_seconds", results["evidence_first"]["elapsed_seconds"])


def test_real_model_abstains_when_candidate_list_is_empty(record_property):
    if os.environ.get("PHASE2D1_RUN") != "1":
        pytest.skip("set PHASE2D1_RUN=1 for the approved synthetic-only Ollama evaluation")
    _verify_fixtures()
    version, models = local_environment()
    if version != "0.34.2" or MODEL not in models:
        pytest.skip("required local Ollama server/model unavailable")
    case = CASES[0]
    finding, context, _expanded, bundle, _request = _eligible(case)
    empty = bundle.model_copy(update={"candidates": ()})
    provider = OllamaProvider(MODEL, timeout=120)
    started = perf_counter()
    try:
        validation, response_size, request_size = _run_evidence_first(provider, finding, context, empty)
        outcome = validation.review
        record = {
            "status": "completed" if outcome else validation.code,
            "assessment": outcome.assessment.value if outcome else None,
            "candidate_count": 0,
            "selected_candidate_count": (len(outcome.supporting_evidence) + len(outcome.counter_evidence))
            if outcome else 0,
            "schema_valid": validation.schema_valid,
            "references_valid": validation.references_valid,
            "request_bytes": request_size,
            "response_bytes": response_size,
            "elapsed_seconds": round(perf_counter() - started, 3),
        }
    except OllamaError as exc:
        code = exc.code if exc.code in _SAFE_PROVIDER_CODES else "provider_error"
        record = {"status": code, "assessment": None, "candidate_count": 0,
                  "selected_candidate_count": 0, "elapsed_seconds": round(perf_counter() - started, 3)}
    print(json.dumps({"case": "empty_candidate_control", "model": MODEL,
                      "ollama_version": version, **record}, sort_keys=True))
    record_property("case", "empty_candidate_control")
    record_property("status", record["status"] or "none")
    record_property("assessment", record["assessment"] or "none")
    record_property("selected_candidate_count", record["selected_candidate_count"])
