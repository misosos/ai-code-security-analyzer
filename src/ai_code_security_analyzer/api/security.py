"""Host, Origin, request-size, and local token boundaries."""

from __future__ import annotations

import hmac
import json
import math
import re
import unicodedata
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Message, Receive, Scope, Send


MAX_REQUEST_BYTES = 16_384
MAX_REQUEST_CHUNKS = 64
SECURITY_HEADERS = (
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
)


class SecurityHeadersMiddleware:
    """Apply browser security and no-store headers to all HTTP responses."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        # Keep the familiar FastAPI state handle available to trusted in-process callers.
        self.state = getattr(app, "state", None)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (key, value) for key, value in message.get("headers", [])
                    if key.lower() not in {name for name, _ in SECURITY_HEADERS}
                ]
                headers.extend(SECURITY_HEADERS)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


def _error(status: int, code: str) -> tuple[Message, Message]:
    body = json.dumps({"error": code}, separators=(",", ":")).encode("utf-8")
    return {
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
    }, {"type": "http.response.body", "body": body}


class ApiBoundaryMiddleware:
    """Reject unapproved browser contexts and cap request bodies before parsing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: tuple[str, ...],
        allowed_origins: tuple[str, ...],
        api_token: str,
    ) -> None:
        self.app = app
        self.allowed_hosts = frozenset(item.lower() for item in allowed_hosts)
        self.allowed_origins = frozenset(allowed_origins)
        self.api_token = api_token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw_headers = scope.get("headers", [])
        headers = {key.lower(): value for key, value in raw_headers}
        for singleton in (
            b"host", b"origin", b"content-type", b"content-length", b"x-local-api-token",
            b"access-control-request-method", b"access-control-request-headers",
        ):
            if sum(1 for key, _ in raw_headers if key.lower() == singleton) > 1:
                start, body = _error(400, "invalid_request")
                await send(start)
                await send(body)
                return
        host = headers.get(b"host", b"").decode("latin-1")
        try:
            parsed = urlsplit("//" + host)
            hostname = parsed.hostname
            _ = parsed.port
            valid_host = (
                hostname is not None and hostname.lower() in self.allowed_hosts
                and parsed.username is None and parsed.password is None
                and parsed.path == "" and parsed.query == "" and parsed.fragment == ""
            )
        except ValueError:
            valid_host = False
        if not valid_host:
            start, body = _error(400, "host_not_allowed")
            await send(start)
            await send(body)
            return
        origin = headers.get(b"origin")
        if origin is not None and origin.decode("latin-1") not in self.allowed_origins:
            start, body = _error(403, "origin_not_allowed")
            await send(start)
            await send(body)
            return
        path = scope.get("path", "")
        method = scope.get("method", "")
        protected = method == "POST" and path == "/api/v1/scans"
        investigation_namespace = path == "/api/v2" or path.startswith("/api/v2/")
        protected = protected or investigation_namespace
        if investigation_namespace and method == "OPTIONS":
            request_method = headers.get(b"access-control-request-method", b"").decode("latin-1").upper()
            requested_headers = {
                item.strip().lower() for item in headers.get(b"access-control-request-headers", b"").decode("latin-1").split(",")
                if item.strip()
            }
            if (
                origin is None or request_method != "POST"
                or not requested_headers.issubset({b"content-type".decode(), b"x-local-api-token".decode()})
            ):
                start, body = _error(400, "invalid_request")
                await send(start)
                await send(body)
                return
            # CORS middleware handles only a read-only preflight; no body or
            # registry action is routed through the investigation handlers.
            await self.app(scope, receive, send)
            return
        if protected:
            token = headers.get(b"x-local-api-token", b"").decode("latin-1")
            if not valid_token(token, self.api_token):
                start, body = _error(401, "unauthorized")
                await send(start)
                await send(body)
                return
            if method == "POST":
                content_type = headers.get(b"content-type", b"").decode("latin-1").lower()
                parts = [item.strip() for item in content_type.split(";")]
                if parts[0] != "application/json" or any(item not in {"charset=utf-8", 'charset="utf-8"'} for item in parts[1:]):
                    start, body = _error(415, "invalid_content_type")
                    await send(start)
                    await send(body)
                    return
            content_length = headers.get(b"content-length")
            advertised_length: int | None = None
            if content_length is not None:
                try:
                    if not re.fullmatch(rb"[0-9]{1,10}", content_length):
                        raise ValueError
                    advertised_length = int(content_length)
                    if advertised_length < 0 or advertised_length > MAX_REQUEST_BYTES:
                        raise ValueError
                except ValueError:
                    start, body = _error(413, "invalid_request")
                    await send(start)
                    await send(body)
                    return
            body_bytes = b""
            if method == "POST":
                chunks: list[bytes] = []
                size = 0
                chunk_count = 0
                more = True
                while more:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    chunk_count += 1
                    chunk_limit = MAX_REQUEST_CHUNKS if investigation_namespace else 128
                    if chunk_count > chunk_limit:
                        start, body = _error(413, "invalid_request")
                        await send(start)
                        await send(body)
                        return
                    size += len(chunk)
                    if size > MAX_REQUEST_BYTES:
                        start, body = _error(413, "invalid_request")
                        await send(start)
                        await send(body)
                        return
                    chunks.append(chunk)
                    more = message.get("more_body", False)
                body_bytes = b"".join(chunks)
                if investigation_namespace:
                    if advertised_length is not None and advertised_length != size:
                        start, body = _error(400, "invalid_request")
                        await send(start)
                        await send(body)
                        return
                    try:
                        _validate_strict_json(body_bytes)
                    except (ValueError, UnicodeError, RecursionError):
                        start, body = _error(400, "invalid_request")
                        await send(start)
                        await send(body)
                        return
            delivered = False

            async def replay_body() -> Message:
                nonlocal delivered
                if delivered:
                    # Preserve the original disconnect channel for handlers that
                    # probe request liveness after parsing the buffered body.
                    return await receive()
                delivered = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}

            async def send_with_disconnect_cleanup(message: Message) -> None:
                try:
                    await send(message)
                except BaseException:
                    state = scope.get("state")
                    run_handle = state.get("investigation_run_handle") if isinstance(state, dict) else None
                    session_handle = state.get("investigation_session_handle") if isinstance(state, dict) else None
                    app = scope.get("app")
                    registry = getattr(getattr(app, "state", None), "investigation_registry", None)
                    if isinstance(run_handle, str) and registry is not None:
                        try:
                            registry.release_run(run_handle)
                        except Exception:
                            pass
                        state.pop("investigation_run_handle", None)
                    if isinstance(session_handle, str) and registry is not None:
                        try:
                            registry.release_session(session_handle)
                        except Exception:
                            pass
                        state.pop("investigation_session_handle", None)
                    raise

            await self.app(scope, replay_body, send_with_disconnect_cleanup)
            return
        await self.app(scope, receive, send)


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid_json_constant")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate_json_key")
        output[key] = value
    return output


def _validate_json_tree(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise ValueError("json_nesting_exceeded")
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        if any(unicodedata.category(char).startswith("C") for char in value):
            raise ValueError("control_character")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non_finite_number")
    elif isinstance(value, dict):
        if len(value) > 16:
            raise ValueError("json_object_too_large")
        for key, item in value.items():
            _validate_json_tree(key, depth=depth + 1)
            _validate_json_tree(item, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 16:
            raise ValueError("json_array_too_large")
        for item in value:
            _validate_json_tree(item, depth=depth + 1)


def _validate_strict_json(body: bytes) -> None:
    text = body.decode("utf-8", errors="strict")
    value = json.loads(text, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError("json_top_level_invalid")
    _validate_json_tree(value)


def valid_token(candidate: str | None, expected: str) -> bool:
    if not isinstance(candidate, str) or not candidate or len(candidate) > 256:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


__all__ = ["ApiBoundaryMiddleware", "SecurityHeadersMiddleware", "valid_token"]
