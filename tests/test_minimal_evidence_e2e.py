"""Opt-in four-call comparison on the pinned synthetic direct_flow fixture only."""

from __future__ import annotations

import hashlib
import json
import os
from time import perf_counter

import pytest

from ai_code_security_analyzer.ai_review import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from ai_code_security_analyzer.evidence_candidates import (
    build_evidence_first_request,
    validate_evidence_first_response,
)
from ai_code_security_analyzer.minimal_evidence import (
    MINIMAL_EVIDENCE_INSTRUCTIONS,
    minimal_evidence_response_schema,
    validate_minimal_evidence_response,
)
from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.ollama_provider import OllamaError, _exchange, _local_entry
from test_evidence_first_ollama_e2e import (
    MODEL,
    _evidence_payload,
    _eligible,
    _verify_fixtures,
)
from test_evidence_first_diagnostics import _compact


_OPT_IN = "AI_CODE_SECURITY_RUN_OLLAMA"
_FIXTURE_SHA256 = "536dbf5376d1e6f5a8f759674baae2063ab43cb40589b012d132ead4e2f29c3d"
_MODEL_DIGEST = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
_TIMEOUT = 120.0
_CAPS = (256, 512)


def _require_opt_in() -> None:
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip(f"set {_OPT_IN}=1 for four bounded synthetic Ollama calls")


def _minimal_payload(finding, context, bundle, cap: int) -> dict[str, object]:
    request = build_evidence_first_request(finding, context, bundle)
    if request is None:
        raise AssertionError("evidence_request_not_eligible")
    source_lines = [{"line_number": line.number, "text": line.text} for line in request.source_lines]
    candidates = [{
        "candidate_id": candidate.candidate_id,
        "candidate_kind": candidate.candidate_kind.value,
        "start_line": candidate.start_line,
        "end_line": candidate.end_line,
    } for candidate in request.candidates]
    data: dict[str, object] = {
        "model": MODEL,
        "stream": False,
        "think": False,
        "format": minimal_evidence_response_schema(),
        "options": {"temperature": 0, "num_predict": cap},
        "messages": [
            {"role": "system", "content": "\n".join(MINIMAL_EVIDENCE_INSTRUCTIONS)},
            {"role": "user", "content": json.dumps({
                "trust_label": "untrusted_source_code",
                "finding": request.finding.model_dump(mode="json"),
                "context": request.context.model_dump(mode="json"),
                "source_lines": source_lines,
                "source_context_id": request.source_context_id,
                "candidates": candidates,
            }, ensure_ascii=False)},
        ],
    }
    if len(_compact(data)) > MAX_REQUEST_BYTES:
        raise AssertionError("request_size_limit")
    return data


def _classify_completion(envelope: dict[str, object], cap: int) -> str:
    if envelope.get("done") is not True:
        return "incomplete_response"
    if envelope.get("done_reason") == "length" or (
        type(envelope.get("eval_count")) is int and envelope["eval_count"] >= cap
    ):
        return "token_limit_reached"
    if envelope.get("done_reason") != "stop":
        return "completion_reason_unverified"
    return "normal_completion"


def test_minimal_gate_is_exact_and_precedes_local_inventory(monkeypatch):
    import sys

    module = sys.modules[__name__]

    def forbidden_inventory(*_args, **_kwargs):
        pytest.fail("Ollama inventory queried before exact opt-in")

    monkeypatch.setattr(module, "_exchange", forbidden_inventory)
    for value in (None, "", "0", "true", "yes", " 1"):
        if value is None:
            monkeypatch.delenv(_OPT_IN, raising=False)
        else:
            monkeypatch.setenv(_OPT_IN, value)
        with pytest.raises(pytest.skip.Exception, match="AI_CODE_SECURITY_RUN_OLLAMA=1"):
            test_minimal_evidence_contract_and_candidate_use(256, lambda *_: None)


def test_token_limit_completion_is_rejected_even_if_json_would_parse():
    assert _classify_completion({"done": True, "done_reason": "length", "eval_count": 256}, 256) == "token_limit_reached"
    assert _classify_completion({"done": True, "done_reason": "stop", "eval_count": 123}, 256) == "normal_completion"
    assert _classify_completion({"done": True, "eval_count": 100}, 256) == "completion_reason_unverified"
    assert _classify_completion({"done": False}, 256) == "incomplete_response"


@pytest.mark.parametrize("cap", _CAPS)
def test_minimal_evidence_contract_and_candidate_use(cap, record_property):
    # The opt-in is checked before fixture preparation, inventory, or inference.
    _require_opt_in()
    _verify_fixtures()
    case = next(item for item in __import__("test_evidence_first_ollama_e2e").CASES
                if item.case_id == "direct_flow")
    finding, context, _expanded, bundle, request = _eligible(case)
    from test_evidence_first_ollama_e2e import _fixture

    fixture = _fixture(case)
    fixture_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    if fixture_hash != _FIXTURE_SHA256:
        pytest.fail("approved_fixture_hash_mismatch")

    # Four calls total: legacy/minimal at 256 and 512. Rotate ordering by cap.
    order = (("legacy", "minimal") if cap == 256 else ("minimal", "legacy"))
    responses: dict[str, dict[str, object]] = {}
    version_value = _exchange("GET", "/api/version", None, 5.0).get("version")
    tags_value = _exchange("GET", "/api/tags", None, 5.0).get("models")
    if version_value != "0.34.2" or not isinstance(tags_value, list):
        pytest.skip("required_local_ollama_version_unavailable")
    model_info = next((item for item in tags_value if isinstance(item, dict)
                       and item.get("name") == MODEL and _local_entry(item)), None)
    if model_info is None or model_info.get("digest") != _MODEL_DIGEST:
        pytest.skip("required_pinned_local_model_unavailable")

    legacy_payload = _evidence_payload(request)
    legacy_payload["options"] = {"temperature": 0, "num_predict": cap}
    minimal_payload = _minimal_payload(finding, context, bundle, cap)
    payloads = {"legacy": legacy_payload, "minimal": minimal_payload}
    candidate_map = {item.candidate_id: item for item in bundle.candidates}
    for condition in order:
        payload = payloads[condition]
        body = _compact(payload)
        if len(body) > MAX_REQUEST_BYTES:
            pytest.fail("request_size_limit")
        started = perf_counter()
        try:
            envelope = _exchange("POST", "/api/chat", body, _TIMEOUT)
            elapsed = round(perf_counter() - started, 4)
            message = envelope.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            response_bytes = len(content.encode("utf-8")) if isinstance(content, str) else None
            completion = _classify_completion(envelope, cap)
            code = None
            review = None
            schema_valid: bool | None = None
            refs_valid: bool | None = None
            json_valid: bool | None = None
            selected_ids: tuple[str, ...] = ()
            assessment = None
            if (not isinstance(content, str) or response_bytes is None
                    or response_bytes > MAX_RESPONSE_BYTES):
                completion = "response_size_limit"
                code = "response_size_limit"
            else:
                try:
                    json.loads(content)
                except (UnicodeError, ValueError):
                    json_valid = False
                else:
                    json_valid = True
                if envelope.get("done") is not True or not isinstance(message, dict) or message.get("tool_calls"):
                    completion = "invalid_response"
                    code = "invalid_response"
                elif completion != "normal_completion":
                    code = completion
                elif not json_valid:
                    code = "invalid_json"
            if completion == "normal_completion" and code is None and condition == "legacy":
                if json_valid:
                    checked = validate_evidence_first_response(content, finding, context, bundle)
                    review = checked.review
                    code = checked.code
                    schema_valid = checked.schema_valid
                    refs_valid = checked.references_valid
                    if review:
                        assessment = review.assessment.value
                        selected_ids = tuple(item.candidate_id for item in
                                             (*review.supporting_evidence, *review.counter_evidence))
            elif completion == "normal_completion" and code is None:
                checked = validate_minimal_evidence_response(content, finding, context, bundle)
                review = checked.review
                code = checked.code
                schema_valid = checked.schema_valid
                refs_valid = checked.references_valid
                if review:
                    assessment = review.assessment.value
                    selected_ids = review.selected_candidate_ids

            selected = [candidate_map[item] for item in selected_ids if item in candidate_map]
            user_object = json.loads(payload["messages"][1]["content"])
            candidate_metadata = user_object.get("candidates", [])
            kind_counts: dict[str, int] = {}
            for candidate in selected:
                kind = candidate.candidate_kind.value
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
            expected_anchors = set(case.relevant_candidates)
            selected_anchors = {(item.candidate_kind.value, line) for item in selected
                                for line in range(item.start_line, item.end_line + 1)}
            outcome = {
                "condition": condition,
                "cap": cap,
                "request_bytes": len(body),
                "schema_bytes": len(_compact(payload["format"])),
                "required_output_fields": len(payload["format"].get("required", [])),
                "candidate_count": len(candidate_metadata),
                "candidate_metadata_bytes": len(_compact(candidate_metadata)),
                "response_bytes": response_bytes,
                "completion": completion,
                "code": code,
                "json_valid": json_valid,
                "schema_valid": schema_valid,
                "references_valid": refs_valid,
                "assessment": assessment,
                "matches_expected_assessment": assessment == case.expected,
                "missing_context_reason_present": bool(review and getattr(review, "missing_context_reason", None)),
                "selected_candidate_count": len(selected_ids),
                "selected_candidate_kinds": kind_counts,
                "expected_anchor_overlap_count": len(expected_anchors & selected_anchors),
                "semantic_claims_verified": False,
                "elapsed_seconds": elapsed,
                **{key: envelope[key] for key in (
                    "total_duration", "load_duration", "prompt_eval_count",
                    "prompt_eval_duration", "eval_count", "eval_duration", "done_reason",
                ) if key in envelope},
            }
        except OllamaError as exc:
            elapsed = round(perf_counter() - started, 4)
            outcome = {"condition": condition, "cap": cap, "completion": "provider_error",
                       "code": exc.code, "elapsed_seconds": elapsed}
        assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None
        responses[condition] = outcome

    print(json.dumps({
        "case": "direct_flow", "fixture_sha256": fixture_hash,
        "model": MODEL, "model_digest": _MODEL_DIGEST, "ollama_version": version_value,
        "temperature": 0, "num_predict": cap, "order": order,
        "legacy": responses.get("legacy"), "minimal": responses.get("minimal"),
    }, sort_keys=True))
    record_property("model", MODEL)
    record_property("model_digest", _MODEL_DIGEST)
    record_property("ollama_version", version_value)
    record_property("fixture_sha256", fixture_hash)
    record_property("cap", cap)
    record_property("order", ",".join(order))
    for condition, values in responses.items():
        for key in ("completion", "code", "assessment", "schema_valid", "references_valid",
                    "selected_candidate_count", "elapsed_seconds", "eval_count", "eval_duration",
                    "prompt_eval_count", "prompt_eval_duration", "total_duration", "done_reason"):
            if key in values:
                record_property(f"{condition}_{key}", values[key])
