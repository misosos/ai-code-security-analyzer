"""FastAPI application factory for the loopback-only local API."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from ai_code_security_analyzer.api.routes import router
from ai_code_security_analyzer.api.schemas import ErrorResponse
from ai_code_security_analyzer.api.security import ApiBoundaryMiddleware, SecurityHeadersMiddleware
from ai_code_security_analyzer.services.scan_service import ApiSettings, ProjectTarget, ScanService


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("target_configuration_ambiguous")
        result[key] = value
    return result


def create_app(
    settings: ApiSettings,
    *,
    scan_service: ScanService | None = None,
    static_directory: Path | None = None,
) -> SecurityHeadersMiddleware:
    app = FastAPI(
        title="AI Code Security Analyzer Local API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        debug=False,
    )
    app.state.api_settings = settings
    app.state.scan_service = scan_service or ScanService(settings)

    # Exact configured loopback Origins only; no wildcard and no credentials.
    # Boundary middleware is outermost, so preflight still passes Host/Origin checks.
    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-Local-API-Token"],
            allow_credentials=False,
            max_age=300,
        )
    app.add_middleware(
        ApiBoundaryMiddleware,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.allowed_origins,
        api_token=settings.api_token,
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_request").model_dump())

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content=ErrorResponse(error="internal_error").model_dump())

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "invalid_request"
        return JSONResponse(status_code=exc.status_code, content=ErrorResponse(error=code).model_dump())

    app.include_router(router, prefix="/api/v1")
    ui_directory = static_directory or (Path(__file__).resolve().parents[3] / "frontend" / "dist")
    if ui_directory.is_dir():
        app.mount("/", StaticFiles(directory=ui_directory, html=True, check_dir=True), name="dashboard")
    # Wrap outside Starlette's ServerErrorMiddleware so sanitized 500 responses, as
    # well as boundary denials and preflight/static responses, receive the same headers.
    return SecurityHeadersMiddleware(app)


def create_app_from_env() -> SecurityHeadersMiddleware:
    target_present = "AI_CODE_SECURITY_TARGET" in os.environ
    targets_present = "AI_CODE_SECURITY_TARGETS" in os.environ
    target_value = os.environ.get("AI_CODE_SECURITY_TARGET")
    targets_value = os.environ.get("AI_CODE_SECURITY_TARGETS")
    token = os.environ.get("AI_CODE_SECURITY_API_TOKEN")
    if (not target_present and not targets_present) or not token:
        raise RuntimeError("local_api_configuration_required") from None
    if target_present and targets_present:
        raise RuntimeError("local_api_configuration_invalid") from None
    default_rules = Path(__file__).resolve().parents[3] / "rules"
    rules_value = os.environ.get("AI_CODE_SECURITY_RULES_DIR")
    origins = tuple(
        item.strip() for item in os.environ.get("AI_CODE_SECURITY_ALLOWED_ORIGINS", "").split(",") if item.strip()
    )
    try:
        project_targets: tuple[ProjectTarget, ...] = ()
        target_directory: Path | None = None
        if targets_value is not None:
            if not targets_value or len(targets_value.encode("utf-8")) > 65_536:
                raise ValueError("target_configuration_invalid")
            decoded = json.loads(targets_value, object_pairs_hook=_unique_json_object)
            if not isinstance(decoded, list) or not 1 <= len(decoded) <= 32:
                raise ValueError("target_configuration_invalid")
            parsed: list[ProjectTarget] = []
            for entry in decoded:
                if not isinstance(entry, dict) or set(entry) != {"id", "label", "path"}:
                    raise ValueError("target_configuration_invalid")
                if not all(isinstance(entry[key], str) for key in ("id", "label", "path")):
                    raise ValueError("target_configuration_invalid")
                path = Path(entry["path"])
                if not path.is_absolute():
                    raise ValueError("target_configuration_invalid")
                parsed.append(ProjectTarget(entry["id"], entry["label"], path))
            project_targets = tuple(parsed)
        else:
            target_directory = Path(target_value)
        settings = ApiSettings(
            target_directory=target_directory,
            trusted_rules_directory=Path(rules_value) if rules_value else default_rules,
            api_token=token,
            allowed_origins=origins,
            project_targets=project_targets,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        raise RuntimeError("local_api_configuration_invalid") from None
    return create_app(settings)
