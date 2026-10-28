"""Evaluation-only output-token-cap experiment on pinned synthetic input.

No production provider behavior is changed. Live calls require an explicit gate;
only allowlisted metadata is emitted, never request or response content.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

import pytest

from ai_code_security_analyzer.ai_review import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    build_review_request,
)
from ai_code_security_analyzer.code_context import ContextStatus
from ai_code_security_analyzer.evidence_candidates import (
    build_evidence_first_request,
    validate_evidence_first_response,
)
from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.ollama_provider import (
    OllamaProvider,
    _exchange,
    _local_entry,
)
from test_evidence_first_diagnostics import (
    _request_variants,
    _safe_stats,
    _timed_exchange,
    _compact,
    _inventory,
    _validate_envelope,
    _TIMEOUT_SECONDS,
)
from test_evidence_first_ollama_e2e import MODEL, _evidence_payload


_CAPS = (256, 512, 768)


def _loaded_model_metadata() -> list[dict[str, object]]:
    value = _exchange("GET", "/api/ps", None, 5.0).get("models")
    if not isinstance(value, list):
        return []
    return [{key: item.get(key) for key in ("name", "size", "size_vram")}
            for item in value if isinstance(item, dict) and item.get("name") == MODEL]


def _with_num_predict(payload: dict[str, object], value: int) -> dict[str, object]:
    if type(value) is not int or value not in _CAPS:
        raise ValueError("invalid_num_predict")
    result = json.loads(_compact(payload))
    result["options"]["num_predict"] = value
    return result


def test_num_predict_option_is_evaluation_only_and_bounded():
    _finding, _context, _bundle, variants = _request_variants()
    for variant in variants:
        assert "num_predict" not in variant.payload["options"]
        capped = _with_num_predict(variant.payload, 256)
        assert capped["options"] == {"temperature": 0, "num_predict": 256}
        changed = dict(capped)
        changed["options"] = {"temperature": 0}
        assert _compact(changed) == _compact(variant.payload)
    for invalid in (0, -1, 1.5, True, 255, 1024, "256"):
        with pytest.raises(ValueError, match="invalid_num_predict"):
            _with_num_predict(variants[0].payload, invalid)
    assert OllamaProvider(MODEL).timeout == 60.0


def test_token_cap_classifier_never_accepts_unknown_or_length_completion():
    def classify(envelope: dict[str, object], cap: int) -> str:
        if envelope.get("done") is not True:
            return "incomplete_response"
        reason = envelope.get("done_reason")
        if reason == "length" or envelope.get("eval_count", 0) >= cap:
            return "token_limit_reached"
        if reason == "stop":
            return "normal_completion"
        return "completion_reason_unverified"

    assert classify({"done": True, "done_reason": "length", "eval_count": 256}, 256) == "token_limit_reached"
    assert classify({"done": True, "done_reason": "stop", "eval_count": 120}, 256) == "normal_completion"
    assert classify({"done": True, "eval_count": 100}, 256) == "completion_reason_unverified"
    assert classify({"done": False}, 256) == "incomplete_response"


def test_real_num_predict_pilot_on_direct_flow(record_property):
    if os.environ.get("PHASE2D3_RUN") != "1":
        pytest.skip("set PHASE2D3_RUN=1 for bounded synthetic Ollama token-cap pilot")

    finding, context, bundle, variants = _request_variants()
    if context.metadata.status is not ContextStatus.AVAILABLE:
        pytest.fail("synthetic_context_not_eligible")
    if finding.status is not FindingStatus.UNVERIFIED or finding.confirmation is not None:
        pytest.fail("finding_state_changed")
    baseline_request = build_review_request(finding, context)
    evidence_request = build_evidence_first_request(finding, context, bundle)
    if baseline_request is None or evidence_request is None:
        pytest.fail("review_request_not_eligible")
    baseline_payload = variants[0].payload
    evidence_payload = _evidence_payload(evidence_request)
    if _compact(evidence_payload) != _compact(variants[3].payload):
        pytest.fail("canonical_evidence_payload_mismatch")

    inventory = _inventory()
    version_data = _exchange("GET", "/api/version", None, 5.0)
    tags = _exchange("GET", "/api/tags", None, 5.0).get("models")
    if version_data.get("version") != "0.34.2" or not isinstance(tags, list) or not any(
        isinstance(item, dict) and item.get("name") == MODEL and _local_entry(item)
        for item in tags
    ):
        pytest.skip("pinned local Ollama server/model unavailable")
    matching = next(item for item in tags if item.get("name") == MODEL)
    digest = matching.get("digest")
    if not isinstance(digest, str) or len(digest) != 64:
        pytest.fail("model_digest_unavailable")

    cap_value = int(os.environ.get("PHASE2D3_CAP", "256"))
    if cap_value not in _CAPS:
        pytest.fail("invalid_num_predict")
    # Fixed pair per invocation; cap changes only through this explicit gate.
    # 768 is never run automatically and requires a separate review decision.
    runs = [(cap_value, "A_baseline", baseline_payload),
            (cap_value, "D_evidence_first", evidence_payload)]
    for cap, condition, payload in runs:
        capped_payload = _with_num_predict(payload, cap)
        body = _compact(capped_payload)
        if len(body) > MAX_REQUEST_BYTES:
            pytest.fail("request_size_limit")
        loaded_before = _loaded_model_metadata()
        started = time.perf_counter()
        envelope, timings = _timed_exchange(body, _TIMEOUT_SECONDS)
        client_seconds = round(time.perf_counter() - started, 4)
        loaded_after = _loaded_model_metadata()
        if "status" in envelope:
            validation: dict[str, object] = {"status": envelope["status"], "schema_valid": None,
                                             "references_valid": None}
        else:
            message = envelope.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            content_bytes = len(content.encode("utf-8")) if isinstance(content, str) else None
            if not isinstance(content, str) or content_bytes > MAX_RESPONSE_BYTES:
                validation = {"status": "response_size_limit", "schema_valid": None,
                              "references_valid": None}
            else:
                validation = _validate_envelope(
                    envelope, finding, context, bundle, condition == "D_evidence_first"
                )
            content_bytes = content_bytes if isinstance(content, str) else None
            reason = envelope.get("done_reason")
            eval_count = envelope.get("eval_count")
            if reason == "length" or (isinstance(eval_count, int) and eval_count >= cap):
                completion = "token_limit_reached"
            elif envelope.get("done") is not True:
                completion = "incomplete_response"
            elif reason == "stop":
                completion = "normal_completion"
            else:
                completion = "completion_reason_unverified"
            if completion != "normal_completion":
                validation["status_before_completion_gate"] = validation.get("status")
                validation["status"] = completion
                validation["review_accepted"] = False
            else:
                validation["review_accepted"] = validation.get("status") == "completed"
        message = envelope.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        content_bytes = len(content.encode("utf-8")) if isinstance(content, str) else None
        stats = _safe_stats(envelope)
        eval_count = stats.get("eval_count")
        eval_duration = stats.get("eval_duration")
        generation_tokens_per_second = (
            round(eval_count * 1_000_000_000 / eval_duration, 3)
            if isinstance(eval_count, int) and isinstance(eval_duration, int) and eval_duration > 0
            else None
        )
        selected_kinds: dict[str, int] | None = None
        selected_count: int | None = None
        if condition == "D_evidence_first" and isinstance(content, str):
            checked = validate_evidence_first_response(content, finding, context, bundle)
            if checked.review is not None:
                selected_kinds = {}
                selected_count = 0
                selected = (*checked.review.supporting_evidence, *checked.review.counter_evidence)
                candidate_map = {item.candidate_id: item for item in bundle.candidates}
                for item in selected:
                    candidate = candidate_map.get(item.candidate_id)
                    if candidate is not None:
                        selected_kinds[candidate.candidate_kind.value] = (
                            selected_kinds.get(candidate.candidate_kind.value, 0) + 1
                        )
                        selected_count += 1
        result = {
            "condition": condition,
            "num_predict": cap,
            "payload_bytes": len(body),
            "payload_sha256": hashlib.sha256(body).hexdigest(),
            "schema_bytes": len(_compact(capped_payload["format"])),
            "system_bytes": len(capped_payload["messages"][0]["content"].encode("utf-8")),
            "user_bytes": len(capped_payload["messages"][1]["content"].encode("utf-8")),
            "code_line_count": len(context.lines),
            "candidate_count": len(bundle.candidates) if condition.startswith("D") else 0,
            "candidate_kinds_provided": ({kind: sum(c.candidate_kind.value == kind for c in bundle.candidates)
                                           for kind in sorted({c.candidate_kind.value for c in bundle.candidates})}
                                          if condition.startswith("D") else {}),
            "candidate_selected_count": selected_count,
            "candidate_selected_kinds": selected_kinds,
            "status": validation.get("status"),
            "status_before_completion_gate": validation.get("status_before_completion_gate"),
            "schema_valid": validation.get("schema_valid"),
            "references_valid": validation.get("references_valid"),
            "assessment": validation.get("assessment"),
            "review_accepted": validation.get("review_accepted"),
            "model_output_json_parse_seconds": validation.get("model_output_json_parse_seconds"),
            "review_validation_seconds": validation.get("review_validation_seconds"),
            "completion": completion if "status" not in envelope else "no_completion_metadata",
            "content_bytes": content_bytes,
            "client_seconds": client_seconds,
            "transport_stages": timings,
            "ollama_stats": stats,
            "generation_tokens_per_second": generation_tokens_per_second,
            "loaded_model_before": loaded_before,
            "loaded_model_after": loaded_after,
            "model_digest": digest,
            "inventory": inventory,
        }
        print(json.dumps(result, sort_keys=True), flush=True)
        assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None
        record_property(f"{condition}_{cap}_status", str(result["status"]))
        record_property(f"{condition}_{cap}_seconds", str(client_seconds))

    # Any higher-cap or B/C run is intentionally a separate decision after
    # reviewing both pilot outputs; no automatic retries or unbounded loops.
