"""Versioned local API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ai_code_security_analyzer.api.schemas import ErrorResponse, HealthResponse, OptionsResponse, ScanRequest
from ai_code_security_analyzer.services.scan_service import ScanService, ServiceError


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse()


@router.get("/options", response_model=OptionsResponse)
def options(request: Request) -> OptionsResponse:
    service: ScanService = request.app.state.scan_service
    return OptionsResponse(targets=service.target_options, rule_profiles=service.profile_options)


@router.post("/scans")
def create_scan(payload: ScanRequest, request: Request) -> Response:
    service: ScanService = request.app.state.scan_service
    try:
        result = service.scan(payload.target_id, payload.rule_profile_id)
    except ServiceError as exc:
        return JSONResponse(status_code=exc.status_code, content=ErrorResponse(error=exc.code).model_dump())
    serialized = result.model_dump_json().encode("utf-8")
    if len(serialized) > request.app.state.api_settings.max_response_bytes:
        return JSONResponse(status_code=413, content=ErrorResponse(error="response_limit_exceeded").model_dump())
    return Response(content=serialized, status_code=200, media_type="application/json")
