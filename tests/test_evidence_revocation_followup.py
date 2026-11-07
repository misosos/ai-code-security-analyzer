"""합성 API 입력으로 해제·실패·절대 TTL 경계를 검증한다."""
import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer.investigation_evidence_registry import (
    EvidenceRegistryError, RegistryErrorCode, RUN_TTL_SECONDS, SESSION_TTL_SECONDS,
)
from test_investigation_api import app_for, HEADERS
from test_finding_disappearance_evaluator import bundle, finding


def prepare(tmp_path):
    runs = [bundle(finding(letter), target="local-project") for letter in ("a", "b")]
    app, _ = app_for(tmp_path, runs)
    return app


def scans(client):
    handles = []
    for _ in range(2):
        response = client.post("/api/v2/investigation-scans", headers=HEADERS,
                               json={"target_id": "local-project", "rule_profile_id": "baseline"})
        assert response.status_code == 200
        handles.append(response.json()["run_handle"])
    return handles


def post(client, path, body):
    return client.post("/api/v2/" + path, headers=HEADERS, json=body)


def session(client, handles):
    response = post(client, "investigations", {"baseline_handle": handles[0], "current_handle": handles[1]})
    assert response.status_code == 201
    return response.json()["investigation_handle"]


def test_해제된_세션과_run은_재사용할_수_없고_다른_세션은_독립적이다(tmp_path):
    app = prepare(tmp_path)
    registry = app.state.investigation_registry
    with TestClient(app) as client:
        handles = scans(client)
        for handle in handles:
            registry.get_run(handle)
        first, second = session(client, handles), session(client, handles)
        for handle in (first, second):
            assert post(client, "investigations/evaluate", {"investigation_handle": handle}).status_code == 200
        # 잘못된 kind는 존재 정보를 공개하지 않으며 다른 종류의 레코드를 삭제하지 않는다.
        assert post(client, "investigation-release", {"kind": "run", "handle": first}).status_code == 204
        assert registry.active_session_count == 2
        for _ in range(2):
            assert post(client, "investigation-release", {"kind": "investigation", "handle": first}).status_code == 204
            assert post(client, "investigations/evaluate", {"investigation_handle": first}).status_code == 404
        assert registry.active_session_count == 1
        assert post(client, "investigations/evaluate", {"investigation_handle": second}).status_code == 200
        assert post(client, "investigations", {"baseline_handle": first, "current_handle": handles[1]}).status_code == 404
        assert post(client, "investigation-release", {"kind": "run", "handle": handles[0]}).status_code == 409
        assert post(client, "investigation-release", {"kind": "investigation", "handle": second}).status_code == 204
        for handle in handles:
            assert post(client, "investigation-release", {"kind": "run", "handle": handle}).status_code == 204
            with pytest.raises(EvidenceRegistryError) as error:
                registry.get_run(handle)
            assert error.value.code is RegistryErrorCode.EVIDENCE_UNAVAILABLE
            assert post(client, "investigation-release", {"kind": "run", "handle": handle}).status_code == 204
        assert post(client, "investigations", {"baseline_handle": handles[0], "current_handle": handles[1]}).status_code == 404
    assert registry.active_run_count == registry.active_session_count == registry.stored_bytes == 0


def test_공식_api의_900초_절대_ttl은_조회와_세션생성으로_연장되지_않는다(tmp_path):
    app = prepare(tmp_path)
    registry = app.state.investigation_registry
    now = [100.0]
    registry._clock = lambda: now[0]
    assert RUN_TTL_SECONDS == SESSION_TTL_SECONDS == registry._run_ttl == registry._session_ttl == 900
    with TestClient(app) as client:
        handles = scans(client)
        now[0] = 999.0
        active = session(client, handles)
        assert post(client, "investigations/evaluate", {"investigation_handle": active}).status_code == 200
        registry.get_run(handles[0])
        now[0] = 1000.0
        # 접근 만료와 요청 시 정리를 구분한다. 시간만으로 메모리가 즉시 삭제되지는 않는다.
        assert registry.active_run_count == 2
        response = post(client, "investigations/evaluate", {"investigation_handle": active})
        assert response.status_code == 404 and response.json() == {"error": "evidence_unavailable"}
        assert registry.active_run_count == registry.active_session_count == registry.stored_bytes == 0
        assert post(client, "investigations", {"baseline_handle": handles[0], "current_handle": handles[1]}).status_code == 404
        assert post(client, "investigation-release", {"kind": "investigation", "handle": active}).status_code == 204


def test_미존재와_잘못된_형식의_handle은_기존_오류_계약을_따른다(tmp_path):
    with TestClient(prepare(tmp_path)) as client:
        unknown = "Z" * 43
        assert post(client, "investigations/evaluate", {"investigation_handle": unknown}).status_code == 404
        assert post(client, "investigation-release", {"kind": "run", "handle": unknown}).status_code == 204
        assert post(client, "investigations/evaluate", {"investigation_handle": "invalid"}).status_code == 400
        assert post(client, "investigation-release", {"kind": "run", "handle": "invalid"}).status_code == 400


@pytest.mark.parametrize("unexpected", [False, True])
def test_세션_해제_실패와_부분_성공은_원자적_전체_해제로_표시되지_않는다(tmp_path, monkeypatch, unexpected):
    app = prepare(tmp_path)
    registry = app.state.investigation_registry
    with TestClient(app, raise_server_exceptions=False) as client:
        handles = scans(client)
        active = session(client, handles)
        original = registry.release_session
        def failed(_handle):
            if unexpected:
                raise RuntimeError("synthetic_private_marker")
            raise EvidenceRegistryError(RegistryErrorCode.INTERNAL_UNAVAILABLE)
        monkeypatch.setattr(registry, "release_session", failed)
        response = post(client, "investigation-release", {"kind": "investigation", "handle": active})
        assert response.status_code == (500 if unexpected else 503)
        assert response.json() == {"error": "internal_error" if unexpected else "internal_unavailable"}
        assert post(client, "investigations/evaluate", {"investigation_handle": active}).status_code == 200
        assert post(client, "investigation-release", {"kind": "run", "handle": handles[0]}).status_code == 409
        monkeypatch.setattr(registry, "release_session", original)
        assert post(client, "investigation-release", {"kind": "investigation", "handle": active}).status_code == 204
        assert post(client, "investigation-release", {"kind": "run", "handle": handles[0]}).status_code == 204
        assert registry.active_session_count == 0 and registry.active_run_count == 1
        registry.get_run(handles[1])
        assert post(client, "investigation-release", {"kind": "run", "handle": handles[1]}).status_code == 204
    assert registry.stored_bytes == 0
