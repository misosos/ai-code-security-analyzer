"""FastAPI application factory for the loopback-only local API."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from ai_code_security_analyzer.api.routes import router
from ai_code_security_analyzer.api.schemas import ErrorResponse
from ai_code_security_analyzer.api.security import ApiBoundaryMiddleware
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


def create_app(settings: ApiSettings, *, scan_service: ScanService | None = None) -> FastAPI:
    app = FastAPI(
        title="AI Code Security Analyzer Local API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        debug=False,
    )
    app.state.api_settings = settings
    app.state.scan_service = scan_service or ScanService(settings)
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
    return app


def create_app_from_env() -> FastAPI:
    target_value = os.environ.get("AI_CODE_SECURITY_TARGET")
    token = os.environ.get("AI_CODE_SECURITY_API_TOKEN")
    if not target_value or not token:
        raise RuntimeError("local_api_configuration_required") from None
    default_rules = Path(__file__).resolve().parents[3] / "rules"
    rules_value = os.environ.get("AI_CODE_SECURITY_RULES_DIR")
    origins = tuple(
        item.strip() for item in os.environ.get("AI_CODE_SECURITY_ALLOWED_ORIGINS", "").split(",") if item.strip()
    )
    try:
        settings = ApiSettings(
            target_directory=Path(target_value),
            trusted_rules_directory=Path(rules_value) if rules_value else default_rules,
            api_token=token,
            allowed_origins=origins,
        )
    except (OSError, ValueError):
        raise RuntimeError("local_api_configuration_invalid") from None
    return create_app(settings)
