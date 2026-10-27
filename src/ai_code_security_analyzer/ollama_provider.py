"""Bounded, direct-loopback Ollama transport for local model reviews only."""

import http.client
import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ai_code_security_analyzer.ai_review import (
    AIAnalysisRequest, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ReviewDiagnostics, ReviewOutcome,
    ReviewRunStatus, _ProviderResponse, _request_bytes, _validate_response_detailed,
    _safe_public_text, _safe_source_line, build_review_request,
)
from ai_code_security_analyzer.code_context import ContextPolicy, ContextStatus, extract_code_context
from ai_code_security_analyzer.models import Finding

_HOST = "127.0.0.1"
_PORT = 11434
_MAX_ENVELOPE_BYTES = 32_000
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}(?::[A-Za-z0-9][A-Za-z0-9._-]{0,25})?$")
_SAFE_PROVIDER_CODES = frozenset({
    "redirect_rejected", "local_server_error", "response_size_limit", "invalid_json",
    "timeout", "server_unavailable", "invalid_local_inventory", "unsafe_request",
    "model_unavailable", "request_size_limit", "invalid_response",
})


class OllamaError(Exception):
    """Safe issue code only; never carry server responses or source text."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _exchange(method: Literal["GET", "POST"], path: str, payload: bytes | None, timeout: float) -> dict:
    connection = http.client.HTTPConnection(_HOST, _PORT, timeout=timeout)
    try:
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            raise OllamaError("redirect_rejected")
        if response.status != 200:
            raise OllamaError("local_server_error")
        raw = response.read(_MAX_ENVELOPE_BYTES + 1)
        if len(raw) > _MAX_ENVELOPE_BYTES:
            raise OllamaError("response_size_limit")
        try:
            value = json.loads(raw)
        except (UnicodeError, ValueError) as exc:
            raise OllamaError("invalid_json") from None
        if not isinstance(value, dict):
            raise OllamaError("invalid_json")
        return value
    except (socket.timeout, TimeoutError) as exc:
        raise OllamaError("timeout") from None
    except (ConnectionError, OSError, http.client.HTTPException) as exc:
        raise OllamaError("server_unavailable") from None
    finally:
        connection.close()


def local_environment(timeout: float = 3.0) -> tuple[str, tuple[str, ...]]:
    """Return local server version and locally stored model names; no inference."""
    version = _exchange("GET", "/api/version", None, timeout).get("version")
    tags = _exchange("GET", "/api/tags", None, timeout).get("models")
    if not isinstance(version, str) or not isinstance(tags, list):
        raise OllamaError("invalid_local_inventory")
    names = tuple(item["name"] for item in tags if isinstance(item, dict) and
                  isinstance(item.get("name"), str) and _local_entry(item))
    return version, names


def _local_entry(item: dict) -> bool:
    name = item.get("name")
    digest = item.get("digest")
    size = item.get("size")
    return (isinstance(name, str) and bool(_MODEL_NAME.fullmatch(name)) and
            not name.lower().endswith(":cloud") and
            isinstance(size, int) and not isinstance(size, bool) and size > 0 and
            isinstance(digest, str) and bool(re.fullmatch(r"[0-9a-f]{64}", digest)) and
            "remote_model" not in item)


@dataclass(frozen=True, slots=True)
class OllamaProvider:
    """No configurable endpoint, proxies, redirects, cloud or tool calls."""

    model: str
    timeout: float = 60.0

    def __post_init__(self) -> None:
        if not _MODEL_NAME.fullmatch(self.model) or self.model.lower().endswith(":cloud"):
            raise ValueError("invalid_local_model_name")
        if not 0 < self.timeout <= 120:
            raise ValueError("invalid_timeout")

    def generate(self, request: AIAnalysisRequest) -> str:
        if (request.external_transmission_allowed is not False
                or request.source_trust_label != "untrusted_source_code"
                or any(not _safe_source_line(line.text) for line in request.untrusted_source_lines)
                or not all(_safe_public_text(value) for value in (
                    request.untrusted_finding.finding_id, request.untrusted_finding.rule_id,
                    request.untrusted_finding.file_path, request.untrusted_finding.tool_description,
                ))
                or _request_bytes(request) > MAX_REQUEST_BYTES):
            raise OllamaError("unsafe_request")
        tags = _exchange("GET", "/api/tags", None, min(self.timeout, 5.0)).get("models")
        if not isinstance(tags, list) or not any(
            isinstance(item, dict) and item.get("name") == self.model and _local_entry(item)
            for item in tags
        ):
            raise OllamaError("model_unavailable")
        # The server inventories local model blobs before source is sent.
        data = {
            "model": self.model, "stream": False, "think": False,
            "format": _ProviderResponse.model_json_schema(),
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": "\n".join(request.trusted_instructions)},
                {"role": "user", "content": json.dumps({
                    "trust_label": request.source_trust_label,
                    "finding": request.untrusted_finding.model_dump(mode="json"),
                    "context": request.untrusted_context.model_dump(mode="json"),
                    "source_lines": [
                        {"line_number": line.number, "text": line.text}
                        for line in request.untrusted_source_lines
                    ],
                }, ensure_ascii=False)},
            ],
        }
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise OllamaError("request_size_limit")
        envelope = _exchange("POST", "/api/chat", payload, self.timeout)
        message = envelope.get("message")
        if envelope.get("done") is not True or not isinstance(message, dict) or message.get("tool_calls"):
            raise OllamaError("invalid_response")
        content = message.get("content")
        if not isinstance(content, str):
            raise OllamaError("invalid_response")
        try:
            if len(content.encode("utf-8")) > MAX_RESPONSE_BYTES:
                raise OllamaError("response_size_limit")
            json.loads(content)
        except (UnicodeError, ValueError):
            raise OllamaError("invalid_json") from None
        return content


def run_ollama_review(
    target_root: Path, finding: Finding, provider: OllamaProvider,
    policy: ContextPolicy | None = None, *, end_line: int | None = None,
) -> ReviewOutcome:
    """Review a bounded context; preserve Finding even on provider failure."""
    if type(provider) is not OllamaProvider:
        return ReviewOutcome(ReviewRunStatus.REQUEST_REJECTED, issues=("unsupported_provider",))
    context = extract_code_context(target_root, finding, policy, end_line=end_line)
    if context.metadata.status is ContextStatus.UNAVAILABLE:
        return ReviewOutcome(ReviewRunStatus.INSUFFICIENT_CONTEXT, issues=context.metadata.issues,
                             diagnostics=ReviewDiagnostics("context", "incomplete_context"))
    if context.metadata.redacted or context.metadata.truncated:
        return ReviewOutcome(ReviewRunStatus.INSUFFICIENT_CONTEXT, issues=("incomplete_context",),
                             diagnostics=ReviewDiagnostics("context", "incomplete_context"))
    request = build_review_request(finding, context)
    if request is None:
        return ReviewOutcome(ReviewRunStatus.REQUEST_REJECTED, issues=("unsafe_request",),
                             diagnostics=ReviewDiagnostics("request", "unsafe_request"))
    try:
        request_size = _request_bytes(request)
    except (UnicodeError, ValueError):
        return ReviewOutcome(ReviewRunStatus.REQUEST_REJECTED, issues=("unsafe_request",),
                             diagnostics=ReviewDiagnostics("request", "unsafe_request"))
    if request_size > MAX_REQUEST_BYTES:
        return ReviewOutcome(ReviewRunStatus.REQUEST_TOO_LARGE, issues=("request_size_limit",),
                             diagnostics=ReviewDiagnostics("request", "request_size_limit",
                                                           request_bytes=request_size))
    try:
        raw = provider.generate(request)
    except OllamaError as exc:
        code = exc.code if exc.code in _SAFE_PROVIDER_CODES else "provider_error"
        status = (ReviewRunStatus.RESPONSE_TOO_LARGE if code == "response_size_limit"
                  else ReviewRunStatus.PROVIDER_FAILED)
        return ReviewOutcome(status, issues=(code,),
                             diagnostics=ReviewDiagnostics("provider", code,
                                                           request_bytes=request_size))
    except Exception:
        return ReviewOutcome(ReviewRunStatus.PROVIDER_FAILED, issues=("provider_error",),
                             diagnostics=ReviewDiagnostics("provider", "provider_error",
                                                           request_bytes=request_size))
    response_size = len(raw.encode("utf-8"))
    validation = _validate_response_detailed(raw, finding, context, origin="ollama_local")
    diagnostics = ReviewDiagnostics(
        validation.stage, validation.code, validation.schema_valid,
        validation.references_valid, request_size, response_size,
    )
    if validation.review is None:
        return ReviewOutcome(ReviewRunStatus.VALIDATION_FAILED,
                             issues=(validation.code or "unknown_validation_error",),
                             diagnostics=diagnostics)
    return ReviewOutcome(ReviewRunStatus.COMPLETED, review=validation.review,
                         diagnostics=diagnostics)
