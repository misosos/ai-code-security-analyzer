"""Versioned local API endpoints."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from ai_code_security_analyzer.api.schemas import (
    ErrorResponse, HealthResponse, InvestigationCreateRequest, InvestigationEvaluationResponse,
    InvestigationEvaluateRequest, InvestigationReleaseRequest, InvestigationScanRequest,
    InvestigationScanResponse, InvestigationSessionResponse, OptionsResponse, ScanRequest,
    RuleBytesComparisonResponse,
)
from ai_code_security_analyzer.finding_disappearance_evaluator import MAX_EVALUATION_BYTES
from ai_code_security_analyzer.investigation_evidence_registry import (
    MAX_RUNS, MAX_RUN_RECORD_BYTES, EvidenceRegistryError, RegistryErrorCode, RunEvidenceRegistry,
)
from ai_code_security_analyzer.services.scan_service import ScanService, ServiceError


router = APIRouter()
investigation_router = APIRouter()
MAX_INVESTIGATION_SCAN_RESPONSE_BYTES = MAX_RUN_RECORD_BYTES + 16_384


class AppRateLimiter:
    """Small fixed-state process-wide sliding-window limits, shared by app routes."""

    _limits = {"scan": (2, 60.0), "session": (10, 60.0), "evaluate": (10, 60.0), "release": (30, 60.0)}

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._events = {key: deque() for key in self._limits}
        self._lock = threading.Lock()

    def allow(self, action: str) -> bool:
        maximum, window = self._limits[action]
        now = self._clock()
        with self._lock:
            events = self._events[action]
            while events and now - events[0] >= window:
                events.popleft()
            if len(events) >= maximum:
                return False
            events.append(now)
            return True


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content=ErrorResponse(error=code).model_dump())


def _registry_error(error: EvidenceRegistryError) -> JSONResponse:
    mapping = {
        RegistryErrorCode.EVIDENCE_UNAVAILABLE: (404, "evidence_unavailable"),
        RegistryErrorCode.BINDING_REJECTED: (409, "binding_rejected"),
        RegistryErrorCode.RESOURCE_LIMIT: (429, "resource_limit"),
        RegistryErrorCode.INTERNAL_UNAVAILABLE: (503, "internal_unavailable"),
        RegistryErrorCode.EVALUATION_BUSY: (409, "evaluation_busy"),
    }
    status, code = mapping[error.code]
    return _error(status, code)


def _investigation_enabled(request: Request) -> bool:
    return bool(request.app.state.investigation_api_enabled)


def _limited(request: Request, action: str) -> bool:
    limiter: AppRateLimiter = request.app.state.investigation_rate_limiter
    return limiter.allow(action)


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


@investigation_router.post("/investigation-scans")
async def create_investigation_scan(payload: InvestigationScanRequest, request: Request) -> Response:
    if not _investigation_enabled(request):
        return _error(503, "unsupported_deployment")
    if not _limited(request, "scan"):
        return _error(429, "resource_limit")
    service: ScanService = request.app.state.scan_service
    registry: RunEvidenceRegistry = request.app.state.investigation_registry
    registry.cleanup_expired()
    if registry.active_run_count >= MAX_RUNS:
        return _error(429, "resource_limit")
    try:
        scan, manifest = await run_in_threadpool(
            service._scan_with_manifest, payload.target_id, payload.rule_profile_id,
            investigation_verbose=True,
        )
    except ServiceError as exc:
        return _error(exc.status_code, exc.code)
    except Exception:
        return _error(503, "internal_unavailable")

    # A disconnected caller does not receive an orphaned Handle. The expensive
    # Semgrep subprocess may have completed, but its evidence is discarded.
    try:
        if await request.is_disconnected():
            return _error(499, "request_cancelled")
    except Exception:
        return _error(503, "internal_unavailable")

    # Validate the entire envelope before admitting a record. The handle has a
    # fixed 43-character representation, so this placeholder has exact length.
    try:
        probe = InvestigationScanResponse(
            contract_version="investigation-scan/v1", run_handle="A" * 43, scan=scan,
        ).model_dump_json().encode("utf-8", errors="strict")
    except Exception:
        return _error(500, "internal_unavailable")
    if len(probe) > MAX_INVESTIGATION_SCAN_RESPONSE_BYTES:
        return _error(413, "response_limit_exceeded")
    try:
        handle = registry.register_run(scan, manifest)
    except EvidenceRegistryError as exc:
        return _registry_error(exc)
    try:
        envelope = InvestigationScanResponse(
            contract_version="investigation-scan/v1", run_handle=handle, scan=scan,
        )
        serialized = envelope.model_dump_json().encode("utf-8", errors="strict")
        if len(serialized) > MAX_INVESTIGATION_SCAN_RESPONSE_BYTES:
            raise ValueError("response_limit")
    except Exception:
        try:
            registry.release_run(handle)
        except EvidenceRegistryError:
            pass
        return _error(500, "internal_unavailable")
    request.scope.setdefault("state", {})["investigation_run_handle"] = handle
    return Response(content=serialized, status_code=200, media_type="application/json")


@investigation_router.post("/investigation-scans/rule-bytes")
async def create_rule_bytes_investigation_scan(payload: InvestigationScanRequest, request: Request) -> Response:
    """Opt-in scan with an atomic rule-bytes sidecar; no digest is serialized."""
    if not _investigation_enabled(request):
        return _error(503, "unsupported_deployment")
    if not _limited(request, "scan"):
        return _error(429, "resource_limit")
    service: ScanService = request.app.state.scan_service
    registry: RunEvidenceRegistry = request.app.state.investigation_registry
    registry.cleanup_expired()
    if registry.active_run_count >= MAX_RUNS:
        return _error(429, "resource_limit")
    try:
        scan, manifest, observation = await run_in_threadpool(
            service._scan_with_rule_bytes_manifest, payload.target_id, payload.rule_profile_id,
        )
    except ServiceError as exc:
        return _error(exc.status_code, exc.code)
    except Exception:
        return _error(503, "internal_unavailable")
    try:
        if await request.is_disconnected():
            return _error(499, "request_cancelled")
    except Exception:
        return _error(503, "internal_unavailable")
    try:
        handle: str | None = None
        handle = registry.register_rule_bytes_run(scan, manifest, observation)
        envelope = InvestigationScanResponse(
            contract_version="investigation-scan/v1", run_handle=handle, scan=scan,
        )
        serialized = envelope.model_dump_json().encode("utf-8", errors="strict")
        if len(serialized) > MAX_INVESTIGATION_SCAN_RESPONSE_BYTES:
            raise ValueError("response_limit")
    except EvidenceRegistryError as exc:
        return _registry_error(exc)
    except Exception:
        if handle is not None:
            try:
                registry.release_run(handle)
            except EvidenceRegistryError:
                pass
        return _error(503, "internal_unavailable")
    request.scope.setdefault("state", {})["investigation_run_handle"] = handle
    return Response(content=serialized, status_code=200, media_type="application/json")


@investigation_router.post("/investigations")
def create_investigation(payload: InvestigationCreateRequest, request: Request) -> Response:
    if not _investigation_enabled(request):
        return _error(503, "unsupported_deployment")
    if not _limited(request, "session"):
        return _error(429, "resource_limit")
    registry: RunEvidenceRegistry = request.app.state.investigation_registry
    handle: str | None = None
    try:
        handle = registry.create_session(payload.baseline_handle, payload.current_handle)
        body = InvestigationSessionResponse(
            contract_version="investigation-session/v1", investigation_handle=handle,
        ).model_dump_json().encode("utf-8")
    except EvidenceRegistryError as exc:
        return _registry_error(exc)
    except Exception:
        if handle is not None:
            try:
                registry.release_session(handle)
            except EvidenceRegistryError:
                pass
        return _error(503, "internal_unavailable")
    request.scope.setdefault("state", {})["investigation_session_handle"] = handle
    return Response(content=body, status_code=201, media_type="application/json")


@investigation_router.post("/investigations/evaluate")
def evaluate_investigation(payload: InvestigationEvaluateRequest, request: Request) -> Response:
    if not _investigation_enabled(request):
        return _error(503, "unsupported_deployment")
    if not _limited(request, "evaluate"):
        return _error(429, "resource_limit")
    registry: RunEvidenceRegistry = request.app.state.investigation_registry
    try:
        result = registry.evaluate(payload.investigation_handle)
        validated = InvestigationEvaluationResponse.model_validate(asdict(result))
        body = validated.model_dump_json().encode("utf-8", errors="strict")
        if len(body) > MAX_EVALUATION_BYTES:
            return _error(503, "internal_unavailable")
    except EvidenceRegistryError as exc:
        return _registry_error(exc)
    except Exception:
        return _error(503, "internal_unavailable")
    return Response(content=body, status_code=200, media_type="application/json")


@investigation_router.post("/investigations/rule-bytes/evaluate")
def evaluate_rule_bytes(payload: InvestigationEvaluateRequest, request: Request) -> Response:
    if not _investigation_enabled(request):
        return _error(503, "unsupported_deployment")
    if not _limited(request, "evaluate"):
        return _error(429, "resource_limit")
    registry: RunEvidenceRegistry = request.app.state.investigation_registry
    try:
        result = registry.evaluate_rule_bytes(payload.investigation_handle)
        body = RuleBytesComparisonResponse.model_validate(asdict(result)).model_dump_json().encode("utf-8")
    except EvidenceRegistryError as exc:
        return _registry_error(exc)
    except Exception:
        return _error(503, "internal_unavailable")
    return Response(content=body, status_code=200, media_type="application/json")


@investigation_router.post("/investigation-release")
def release_investigation(payload: InvestigationReleaseRequest, request: Request) -> Response:
    if not _investigation_enabled(request):
        return _error(503, "unsupported_deployment")
    if not _limited(request, "release"):
        return _error(429, "resource_limit")
    registry: RunEvidenceRegistry = request.app.state.investigation_registry
    try:
        if payload.kind == "run":
            registry.release_run(payload.handle)
        else:
            registry.release_session(payload.handle)
    except EvidenceRegistryError as exc:
        return _registry_error(exc)
    return Response(status_code=204)
