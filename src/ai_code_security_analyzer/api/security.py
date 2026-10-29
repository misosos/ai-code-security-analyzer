"""Host, Origin, request-size, and local token boundaries."""

from __future__ import annotations

import hmac
import json
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Message, Receive, Scope, Send


MAX_REQUEST_BYTES = 16_384
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
        for singleton in (b"host", b"origin", b"content-type", b"content-length", b"x-local-api-token"):
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
        if scope.get("method") == "POST" and scope.get("path") == "/api/v1/scans":
            token = headers.get(b"x-local-api-token", b"").decode("latin-1")
            if not valid_token(token, self.api_token):
                start, body = _error(401, "unauthorized")
                await send(start)
                await send(body)
                return
            content_type = headers.get(b"content-type", b"").decode("latin-1").lower()
            parts = [item.strip() for item in content_type.split(";")]
            if parts[0] != "application/json" or any(item not in {"charset=utf-8", "charset=\"utf-8\""} for item in parts[1:]):
                start, body = _error(415, "invalid_content_type")
                await send(start)
                await send(body)
                return
            content_length = headers.get(b"content-length")
            if content_length is not None:
                try:
                    if int(content_length) < 0 or int(content_length) > MAX_REQUEST_BYTES:
                        raise ValueError
                except ValueError:
                    start, body = _error(413, "invalid_request")
                    await send(start)
                    await send(body)
                    return
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
                if chunk_count > 128:
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
            delivered = False

            async def replay_body() -> Message:
                nonlocal delivered
                if delivered:
                    return {"type": "http.request", "body": b"", "more_body": False}
                delivered = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}

            await self.app(scope, replay_body, send)
            return
        await self.app(scope, receive, send)


def valid_token(candidate: str | None, expected: str) -> bool:
    if not isinstance(candidate, str) or not candidate or len(candidate) > 256:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


__all__ = ["ApiBoundaryMiddleware", "SecurityHeadersMiddleware", "valid_token"]
