"""Bounded diagnostics for synthetic-only Evidence-first Ollama requests.

The gated test prints allowlisted metadata only. Source, prompts, responses and
provider exception text remain in memory and are never emitted or persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from dataclasses import dataclass
from http.client import HTTPConnection

import pytest

from ai_code_security_analyzer.ai_review import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    _ProviderResponse,
    _validate_response_detailed,
    build_review_request,
)
from ai_code_security_analyzer.code_context import ContextStatus
from ai_code_security_analyzer.evidence_candidates import (
    EvidenceCandidateBundle,
    build_evidence_candidates,
    build_evidence_first_request,
    evidence_first_response_schema,
    validate_evidence_first_response,
)
from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.ollama_provider import (
    OllamaProvider,
    _HOST,
    _PORT,
    _exchange,
    _local_entry,
)
from test_evidence_first_ollama_e2e import (
    CASES,
    MODEL,
    _evidence_payload,
    _eligible,
)


_TIMEOUT_SECONDS = 120.0
_MAX_ENVELOPE_BYTES = 32_000
_EXPECTED_FIXTURE_SHA256 = "536dbf5376d1e6f5a8f759674baae2063ab43cb40589b012d132ead4e2f29c3d"
_OLLAMA_STATS = (
    "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration",
    "eval_count", "eval_duration", "done_reason",
)


@dataclass(frozen=True)
class RequestVariant:
    name: str
    payload: dict[str, object]
    candidate_count: int
    candidate_metadata_bytes: int
    schema_bytes: int
    required_fields: int
    system_bytes: int
    user_bytes: int


def _compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _untrusted_user(request, *, candidates: list[dict[str, object]] | None = None,
                    source_context_id: str | None = None) -> dict[str, object]:
    finding = getattr(request, "untrusted_finding", getattr(request, "finding", None))
    context = getattr(request, "untrusted_context", getattr(request, "context", None))
    lines = getattr(request, "untrusted_source_lines", getattr(request, "source_lines", ()))
    trust_label = getattr(request, "source_trust_label", "untrusted_source_code")
    value: dict[str, object] = {
        "trust_label": trust_label,
        "finding": finding.model_dump(mode="json"),
        "context": context.model_dump(mode="json"),
        "source_lines": [{"line_number": line.number, "text": line.text} for line in lines],
    }
    if source_context_id is not None:
        value["source_context_id"] = source_context_id
    if candidates is not None:
        value["candidates"] = candidates
    return value


def _variant(name: str, trusted: tuple[str, ...], response_schema: dict[str, object],
             user_value: dict[str, object], candidate_metadata: list[dict[str, object]]) -> RequestVariant:
    system_text = "\n".join(trusted)
    user_text = json.dumps(user_value, ensure_ascii=False)
    payload: dict[str, object] = {
        "model": MODEL,
        "stream": False,
        "think": False,
        "format": response_schema,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
    }
    return RequestVariant(
        name=name, payload=payload, candidate_count=len(candidate_metadata),
        candidate_metadata_bytes=len(_compact(candidate_metadata)),
        schema_bytes=len(_compact(response_schema)),
        required_fields=len(response_schema.get("required", ())),
        system_bytes=len(system_text.encode("utf-8")),
        user_bytes=len(user_text.encode("utf-8")),
    )


def _request_variants() -> tuple[object, object, EvidenceCandidateBundle, tuple[RequestVariant, ...]]:
    case = next(item for item in CASES if item.case_id == "direct_flow")
    finding, context, _expanded, bundle, evidence_request = _eligible(case)
    if context.metadata.status is not ContextStatus.AVAILABLE or finding.line_number != 3:
        raise AssertionError("diagnostic_fixture_not_eligible")
    from test_evidence_first_ollama_e2e import _fixture
    if hashlib.sha256(_fixture(case).read_bytes()).hexdigest() != _EXPECTED_FIXTURE_SHA256:
        raise AssertionError("diagnostic_fixture_hash_mismatch")
    baseline = build_review_request(finding, context)
    evidence = build_evidence_first_request(finding, context, bundle)
    if baseline is None or evidence is None:
        raise AssertionError("diagnostic_request_not_eligible")

    baseline_user = _untrusted_user(baseline)
    baseline_schema = _ProviderResponse.model_json_schema()
    variants = [
        _variant("A_baseline", baseline.trusted_instructions, baseline_schema,
                 baseline_user, []),
    ]
    # B adds only a small candidate list to the same baseline instruction/schema contract.
    minimal = [{"candidate_id": item.candidate_id,
                "candidate_kind": item.candidate_kind.value,
                "start_line": item.start_line, "end_line": item.end_line}
               for item in bundle.candidates]
    variants.append(_variant(
        "B_baseline_plus_minimal_candidates", baseline.trusted_instructions, baseline_schema,
        _untrusted_user(baseline, candidates=minimal), minimal,
    ))
    # C switches the system/response contract while retaining the same minimal candidate manifest.
    variants.append(_variant(
        "C_evidence_contract_plus_minimal_candidates", evidence.trusted_instructions,
        evidence_first_response_schema(),
        _untrusted_user(evidence, candidates=minimal,
                        source_context_id=evidence.source_context_id), minimal,
    ))
    # D is the existing full Evidence-first request, including full candidate provenance metadata.
    full = [item.model_dump(mode="json") for item in bundle.candidates]
    variants.append(_variant(
        "D_full_evidence_first", evidence.trusted_instructions, evidence_first_response_schema(),
        _untrusted_user(evidence, candidates=full,
                        source_context_id=evidence.source_context_id),
        full,
    ))
    if _compact(variants[3].payload) != _compact(_evidence_payload(evidence)):
        raise AssertionError("full_evidence_request_parity_failed")
    return finding, context, bundle, tuple(variants)


def _variant_manifest(variant: RequestVariant) -> dict[str, object]:
    payload = variant.payload
    return {
        "condition": variant.name,
        "payload_bytes": len(_compact(payload)),
        "request_sha256": hashlib.sha256(_compact(payload)).hexdigest(),
        "system_bytes": variant.system_bytes,
        "user_bytes": variant.user_bytes,
        "code_line_count": 4,
        "candidate_count": variant.candidate_count,
        "candidate_metadata_bytes": variant.candidate_metadata_bytes,
        "response_schema_bytes": variant.schema_bytes,
        "required_output_field_count": variant.required_fields,
        "stream": False,
        "temperature": 0,
    }


def test_request_variants_report_safe_structural_metadata_only():
    _finding, context, bundle, variants = _request_variants()
    manifests = [_variant_manifest(item) for item in variants]
    assert [item["condition"] for item in manifests] == [
        "A_baseline", "B_baseline_plus_minimal_candidates",
        "C_evidence_contract_plus_minimal_candidates", "D_full_evidence_first",
    ]
    assert all(item["payload_bytes"] <= MAX_REQUEST_BYTES for item in manifests)
    assert all(item["code_line_count"] == len(context.lines) for item in manifests)
    assert [item["candidate_count"] for item in manifests] == [0, 5, 5, 5]
    assert variants[0].payload["format"] == variants[1].payload["format"]
    assert variants[0].payload["messages"][0] == variants[1].payload["messages"][0]
    a_user = json.loads(variants[0].payload["messages"][1]["content"])
    b_user = json.loads(variants[1].payload["messages"][1]["content"])
    b_without_candidates = dict(b_user)
    b_without_candidates.pop("candidates")
    assert b_without_candidates == a_user
    assert variants[1].payload["options"] == variants[2].payload["options"]
    c_user = json.loads(variants[2].payload["messages"][1]["content"])
    d_user = json.loads(variants[3].payload["messages"][1]["content"])
    c_without_candidates = dict(c_user)
    d_without_candidates = dict(d_user)
    c_without_candidates.pop("candidates")
    d_without_candidates.pop("candidates")
    assert d_without_candidates == c_without_candidates
    assert all(set(item) == {"candidate_id", "candidate_kind", "start_line", "end_line"}
               for item in c_user["candidates"])
    assert all(set(item) > set(c_user["candidates"][0]) for item in d_user["candidates"])
    assert bundle.included_line_numbers == tuple(line.number for line in context.lines)
    print(json.dumps({"payload_manifest": manifests}, sort_keys=True))


def _inventory() -> dict[str, object]:
    started = time.perf_counter()
    version_data = _exchange("GET", "/api/version", None, 5.0)
    version_elapsed = time.perf_counter() - started
    started = time.perf_counter()
    tags = _exchange("GET", "/api/tags", None, 5.0).get("models")
    tags_elapsed = time.perf_counter() - started
    if not isinstance(tags, list) or not any(
        isinstance(item, dict) and item.get("name") == MODEL and _local_entry(item)
        for item in tags
    ):
        raise RuntimeError("model_unavailable")
    return {"ollama_version": version_data.get("version"), "model": MODEL,
            "version_query_seconds": round(version_elapsed, 4),
            "model_inventory_seconds": round(tags_elapsed, 4)}


def _timed_exchange(payload: bytes, timeout: float) -> tuple[dict[str, object], dict[str, object]]:
    """POST directly to fixed loopback and time request, headers, body and decode separately."""
    connection = HTTPConnection(_HOST, _PORT, timeout=timeout)
    deadline = time.monotonic() + timeout
    timings: dict[str, object] = {}
    call_started = time.perf_counter()
    stage = "connect_send"
    try:
        started = time.perf_counter()
        connection.request("POST", "/api/chat", body=payload,
                           headers={"Content-Type": "application/json"})
        timings["connect_send_seconds"] = round(time.perf_counter() - started, 4)

        stage = "headers"
        if connection.sock is not None:
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
        started = time.perf_counter()
        response = connection.getresponse()
        timings["headers_seconds"] = round(time.perf_counter() - started, 4)
        if response.status in (301, 302, 303, 307, 308):
            return {"status": "redirect_rejected"}, timings
        if response.status != 200:
            return {"status": "local_server_error"}, timings

        stage = "response_body"
        chunks: list[bytes] = []
        received = 0
        started = time.perf_counter()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(4096, _MAX_ENVELOPE_BYTES - received + 1))
            if not chunk:
                break
            received += len(chunk)
            if received > _MAX_ENVELOPE_BYTES:
                timings["total_seconds"] = round(time.perf_counter() - call_started, 4)
                timings["response_envelope_bytes"] = received
                return {"status": "response_size_limit"}, timings
            chunks.append(chunk)
        timings["body_seconds"] = round(time.perf_counter() - started, 4)
        timings["response_envelope_bytes"] = received

        stage = "response_json"
        started = time.perf_counter()
        started = time.perf_counter()
        try:
            envelope = json.loads(b"".join(chunks))
        except (UnicodeError, ValueError):
            timings["response_json_seconds"] = round(time.perf_counter() - started, 4)
            timings["total_seconds"] = round(time.perf_counter() - call_started, 4)
            return {"status": "invalid_json"}, timings
        timings["response_json_seconds"] = round(time.perf_counter() - started, 4)
        if not isinstance(envelope, dict):
            return {"status": "invalid_json"}, timings
        timings["total_seconds"] = round(time.perf_counter() - call_started, 4)
        return envelope, timings
    except (socket.timeout, TimeoutError):
        timings["total_seconds"] = round(time.perf_counter() - call_started, 4)
        return {"status": f"timeout_{stage}"}, timings
    except (ConnectionError, OSError, ValueError):
        timings["total_seconds"] = round(time.perf_counter() - call_started, 4)
        return {"status": f"transport_error_{stage}"}, timings
    finally:
        connection.close()


def _timed_stream_exchange(payload: bytes, timeout: float) -> tuple[dict[str, object], dict[str, object]]:
    """Consume bounded Ollama NDJSON chunks without retaining/logging their text."""
    connection = HTTPConnection(_HOST, _PORT, timeout=timeout)
    deadline = time.monotonic() + timeout
    started_call = time.perf_counter()
    stage = "connect_send"
    timings: dict[str, object] = {}
    chunks: list[str] = []
    pending = bytearray()
    envelope_bytes = 0
    chunk_count = 0
    content_bytes = 0
    first_chunk_seconds: float | None = None
    first_content_seconds: float | None = None
    final: dict[str, object] | None = None
    stage = "connect_send"

    def finalize_timings() -> None:
        timings.update({
            "total_seconds": round(time.perf_counter() - started_call, 4),
            "response_envelope_bytes": envelope_bytes,
            "stream_chunk_count": chunk_count,
            "first_response_chunk_seconds": round(first_chunk_seconds, 4) if first_chunk_seconds is not None else None,
            "first_nonempty_content_seconds": round(first_content_seconds, 4) if first_content_seconds is not None else None,
            "content_bytes": content_bytes,
        })

    def consume(frame: bytes) -> None:
        nonlocal chunk_count, content_bytes, first_chunk_seconds, first_content_seconds, final
        if not frame.strip():
            return
        chunk_count += 1
        if first_chunk_seconds is None:
            first_chunk_seconds = time.perf_counter() - started_call
        value = json.loads(frame)
        if not isinstance(value, dict):
            raise ValueError("invalid_stream_frame")
        message = value.get("message")
        if isinstance(message, dict):
            text = message.get("content")
            if isinstance(text, str) and text:
                if first_content_seconds is None:
                    first_content_seconds = time.perf_counter() - started_call
                size = len(text.encode("utf-8"))
                content_bytes += size
                if content_bytes > MAX_RESPONSE_BYTES:
                    raise OverflowError
                chunks.append(text)
        if value.get("done") is True:
            final = value

    try:
        connection.request("POST", "/api/chat", body=payload,
                           headers={"Content-Type": "application/json"})
        stage = "headers"
        if connection.sock is not None:
            connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            return {"status": "redirect_rejected"}, timings
        if response.status != 200:
            return {"status": "local_server_error"}, timings

        stage = "stream_body"
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            part = response.read1(min(4096, _MAX_ENVELOPE_BYTES - envelope_bytes + 1))
            if not part:
                break
            envelope_bytes += len(part)
            if envelope_bytes > _MAX_ENVELOPE_BYTES:
                finalize_timings()
                return {"status": "response_envelope_size_limit"}, timings
            pending.extend(part)
            if len(pending) > _MAX_ENVELOPE_BYTES:
                finalize_timings()
                return {"status": "response_frame_size_limit"}, timings
            while b"\n" in pending:
                frame, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                stage = "stream_frame_parse"
                consume(bytes(frame))
                stage = "stream_body"
        if pending:
            stage = "stream_frame_parse"
            consume(bytes(pending))
        finalize_timings()
        if final is None:
            return {"status": "incomplete_stream"}, timings
        message = final.get("message")
        if not isinstance(message, dict):
            message = {}
        final = dict(final)
        final["message"] = {**message, "content": "".join(chunks)}
        return final, timings
    except OverflowError:
        finalize_timings()
        return {"status": "response_content_size_limit"}, timings
    except (socket.timeout, TimeoutError):
        finalize_timings()
        return {"status": f"timeout_{stage}"}, timings
    except (ConnectionError, OSError, ValueError, UnicodeError):
        timings["total_seconds"] = round(time.perf_counter() - started_call, 4)
        return {"status": f"transport_error_{stage}"}, timings
    finally:
        connection.close()


def _validate_envelope(envelope: dict[str, object], finding, context,
                       bundle: EvidenceCandidateBundle, evidence_first: bool) -> dict[str, object]:
    if "status" in envelope:
        return {"status": envelope["status"]}
    message = envelope.get("message")
    if (envelope.get("done") is not True or not isinstance(message, dict)
            or message.get("tool_calls")):
        return {"status": "invalid_response", "schema_valid": None}
    content = message.get("content")
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_RESPONSE_BYTES:
        return {"status": "response_size_limit", "schema_valid": None}
    started = time.perf_counter()
    try:
        json.loads(content)
    except (UnicodeError, ValueError):
        return {"status": "invalid_json", "schema_valid": False,
                "model_output_json_parse_seconds": round(time.perf_counter() - started, 4)}
    output_json_parse_seconds = round(time.perf_counter() - started, 4)
    started = time.perf_counter()
    if evidence_first:
        checked = validate_evidence_first_response(content, finding, context, bundle)
        result = {
            "status": "completed" if checked.review else checked.code,
            "assessment": checked.review.assessment.value if checked.review else None,
            "schema_valid": checked.schema_valid,
            "references_valid": checked.references_valid,
        }
    else:
        checked = _validate_response_detailed(content, finding, context, origin="ollama_local")
        result = {
            "status": "completed" if checked.review else checked.code,
            "assessment": checked.review.assessment.value if checked.review else None,
            "schema_valid": checked.schema_valid,
            "references_valid": checked.references_valid,
        }
    result["review_validation_seconds"] = round(time.perf_counter() - started, 4)
    result["model_output_json_parse_seconds"] = output_json_parse_seconds
    return result


def _safe_stats(envelope: dict[str, object]) -> dict[str, object]:
    stats: dict[str, object] = {}
    for key in _OLLAMA_STATS:
        value = envelope.get(key)
        if key == "done_reason":
            if isinstance(value, str) and value in {"stop", "length", "load", "unload"}:
                stats[key] = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            stats[key] = value
    return stats


@pytest.mark.parametrize("condition", ["A", "B", "C", "D"])
def test_real_model_request_stage_diagnostics(condition, record_property):
    if os.environ.get("PHASE2D2_RUN") != "1":
        pytest.skip("set PHASE2D2_RUN=1 for the fixed synthetic Ollama diagnostic")
    build_started = time.perf_counter()
    finding, context, bundle, variants = _request_variants()
    request_build_seconds = round(time.perf_counter() - build_started, 4)
    inventory = _inventory()
    variant = variants["ABCD".index(condition)]
    body = _compact(variant.payload)
    if len(body) > MAX_REQUEST_BYTES:
        pytest.fail("diagnostic_request_size_limit")
    before_ps = _exchange("GET", "/api/ps", None, 5.0)
    if finding.status is not FindingStatus.UNVERIFIED or finding.confirmation is not None:
        pytest.fail("finding_state_changed")
    envelope, timings = _timed_exchange(body, _TIMEOUT_SECONDS)
    after_ps = _exchange("GET", "/api/ps", None, 5.0)
    outcome = _validate_envelope(envelope, finding, context, bundle, condition in {"C", "D"})
    actual_stats = _safe_stats(envelope)
    # /api/ps contains no user data; retain only the requested model/memory facts.
    def model_ps(value: dict[str, object]) -> list[dict[str, object]]:
        models = value.get("models")
        if not isinstance(models, list):
            return []
        return [{key: item.get(key) for key in ("name", "size", "size_vram", "expires_at")}
                for item in models if isinstance(item, dict)
                and item.get("name") == MODEL]

    result = {
        **_variant_manifest(variant),
        "request_build_seconds": request_build_seconds,
        "inventory": inventory,
        "status": outcome.get("status"),
        "assessment": outcome.get("assessment"),
        "schema_valid": outcome.get("schema_valid"),
        "references_valid": outcome.get("references_valid"),
        "stages": timings,
        "ollama_completion_stats": actual_stats,
        "loaded_model_before": model_ps(before_ps),
        "loaded_model_after": model_ps(after_ps),
        "configured_timeout_seconds": _TIMEOUT_SECONDS,
    }
    print(json.dumps(result, sort_keys=True), flush=True)
    record_property("condition", variant.name)
    record_property("status", str(outcome.get("status")))
    record_property("elapsed_seconds", str(timings.get("total_seconds")))
    record_property("schema_valid", str(outcome.get("schema_valid")))
    assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None


@pytest.mark.parametrize("_unused", [0])
def test_real_model_streaming_start_diagnostic(_unused, record_property):
    if os.environ.get("PHASE2D2_STREAM") != "1":
        pytest.skip("set PHASE2D2_STREAM=1 for one fixed synthetic streaming diagnostic")
    build_started = time.perf_counter()
    finding, context, bundle, variants = _request_variants()
    request_build_seconds = round(time.perf_counter() - build_started, 4)
    inventory = _inventory()
    variant = variants[3]
    payload = dict(variant.payload)
    payload["stream"] = True
    body = _compact(payload)
    if len(body) > MAX_REQUEST_BYTES:
        pytest.fail("diagnostic_request_size_limit")
    envelope, timings = _timed_stream_exchange(body, _TIMEOUT_SECONDS)
    outcome = _validate_envelope(envelope, finding, context, bundle, True)
    result = {
        **_variant_manifest(variant),
        "request_build_seconds": request_build_seconds,
        "condition": "D_full_evidence_first_streaming_diagnostic",
        "request_sha256": hashlib.sha256(body).hexdigest(),
        "stream": True,
        "inventory": inventory,
        "status": outcome.get("status"),
        "assessment": outcome.get("assessment"),
        "schema_valid": outcome.get("schema_valid"),
        "references_valid": outcome.get("references_valid"),
        "stages": timings,
        "ollama_completion_stats": _safe_stats(envelope),
        "configured_timeout_seconds": _TIMEOUT_SECONDS,
    }
    print(json.dumps(result, sort_keys=True), flush=True)
    record_property("status", str(outcome.get("status")))
    record_property("first_content_seconds", str(timings.get("first_nonempty_content_seconds")))
    assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None


def test_default_provider_timeout_ceiling_unchanged():
    assert OllamaProvider(MODEL).timeout == 60.0
    assert OllamaProvider(MODEL, timeout=_TIMEOUT_SECONDS).timeout == _TIMEOUT_SECONDS
    with pytest.raises(ValueError, match="invalid_timeout"):
        OllamaProvider(MODEL, timeout=_TIMEOUT_SECONDS + 1)


@pytest.mark.parametrize(
    ("failure_stage", "expected_status"),
    [
        ("connect_send", "timeout_connect_send"),
        ("headers", "timeout_headers"),
        ("response_body", "timeout_response_body"),
    ],
)
def test_diagnostic_transport_classifies_timeout_stage(
    failure_stage, expected_status, monkeypatch,
):
    class FakeResponse:
        status = 200

        def read1(self, _size):
            raise socket.timeout

    class FakeConnection:
        sock = None

        def __init__(self, _host, _port, timeout):
            assert timeout == 1.0

        def request(self, *_args, **_kwargs):
            if failure_stage == "connect_send":
                raise socket.timeout

        def getresponse(self):
            if failure_stage == "headers":
                raise socket.timeout
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(__import__(__name__), "HTTPConnection", FakeConnection)
    result, metadata = _timed_exchange(b"{}", 1.0)
    assert result["status"] == expected_status
    assert metadata["total_seconds"] >= 0
    assert "timeout" in result["status"]


def test_diagnostic_transport_bounds_envelope_and_classifies_bad_json(monkeypatch):
    class FakeResponse:
        status = 200

        def __init__(self, chunks):
            self.chunks = iter(chunks)
            self.pending = bytearray()

        def read1(self, size):
            if not self.pending:
                try:
                    self.pending.extend(next(self.chunks))
                except StopIteration:
                    return b""
            result = bytes(self.pending[:size])
            del self.pending[:size]
            return result

    class FakeConnection:
        sock = None
        response = None

        def __init__(self, _host, _port, timeout=None):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return self.response

        def close(self):
            pass

    fake_module = __import__(__name__)
    monkeypatch.setattr(fake_module, "HTTPConnection", FakeConnection)
    FakeConnection.response = FakeResponse([b"not-json", b""])
    invalid, _ = _timed_exchange(b"{}", 1.0)
    assert invalid["status"] == "invalid_json"

    FakeConnection.response = FakeResponse([b"x" * (_MAX_ENVELOPE_BYTES + 1)])
    limited, metadata = _timed_exchange(b"{}", 1.0)
    assert limited["status"] == "response_size_limit"
    assert metadata["response_envelope_bytes"] == _MAX_ENVELOPE_BYTES + 1


def test_diagnostic_stream_tracks_first_text_and_enforces_content_limit(monkeypatch):
    class FakeResponse:
        status = 200

        def __init__(self, body):
            self.body = bytearray(body)

        def read1(self, size):
            value = bytes(self.body[:size])
            del self.body[:size]
            return value

    class FakeConnection:
        sock = None
        response = None

        def __init__(self, _host, _port, timeout=None):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return self.response

        def close(self):
            pass

    fake_module = __import__(__name__)
    monkeypatch.setattr(fake_module, "HTTPConnection", FakeConnection)
    good_stream = (
        json.dumps({"message": {"content": "x"}, "done": False}).encode() + b"\n"
        + json.dumps({"message": {"content": ""}, "done": True,
                      "done_reason": "stop", "eval_count": 1}).encode() + b"\n"
    )
    FakeConnection.response = FakeResponse(good_stream)
    complete, metrics = _timed_stream_exchange(b"{}", 1.0)
    assert complete["done"] is True
    assert metrics["stream_chunk_count"] == 2
    assert metrics["content_bytes"] == 1
    assert metrics["first_nonempty_content_seconds"] is not None
    assert complete["message"]["content"] == "x"

    oversized = json.dumps({
        "message": {"content": "x" * (MAX_RESPONSE_BYTES + 1)}, "done": False,
    }).encode() + b"\n"
    FakeConnection.response = FakeResponse(oversized)
    rejected, rejected_metrics = _timed_stream_exchange(b"{}", 1.0)
    assert rejected["status"] == "response_content_size_limit"
    assert rejected_metrics["content_bytes"] == MAX_RESPONSE_BYTES + 1
