from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.services.scan_service import ApiSettings


TOKEN = "t" * 48


def client_for(tmp_path: Path, **overrides) -> TestClient:
    target = tmp_path / "project"
    rules = tmp_path / "rules"
    target.mkdir(exist_ok=True)
    (rules / "experimental").mkdir(parents=True, exist_ok=True)
    (rules / "security-baseline.yml").write_text("rules: []\n")
    (rules / "experimental" / "javascript-eval-taint.yml").write_text("rules: []\n")
    (rules / "experimental" / "javascript-command-injection-taint.yml").write_text("rules: []\n")
    values = {"target_directory": target, "trusted_rules_directory": rules, "api_token": TOKEN,
              "allowed_hosts": ("testserver", "127.0.0.1", "localhost")}
    values.update(overrides)
    return TestClient(create_app(ApiSettings(**values)))


def test_health_and_options_do_not_disclose_paths_or_enable_cors(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        health = client.get("/api/v1/health")
        options = client.get("/api/v1/options")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "ai-code-security-analyzer"}
    assert options.status_code == 200
    body = json.dumps(options.json())
    assert "project" in body and "baseline" in body
    assert str(tmp_path) not in body
    assert "access-control-allow-origin" not in {key.lower() for key in options.headers}


def test_host_origin_auth_content_type_and_extra_fields_are_rejected(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        assert client.get("/api/v1/health", headers={"host": "evil.example"}).json() == {"error": "host_not_allowed"}
        assert client.get("/api/v1/health", headers={"origin": "https://evil.example"}).json() == {"error": "origin_not_allowed"}
        no_auth = client.post("/api/v1/scans", json={"target_id": "local-project", "rule_profile_id": "baseline"})
        assert no_auth.status_code == 401 and no_auth.json() == {"error": "unauthorized"}
        bad_type = client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN}, content="{}")
        assert bad_type.status_code == 415
        extra = client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN}, json={
            "target_id": "local-project", "rule_profile_id": "baseline", "path": "/etc/passwd"
        })
        assert extra.status_code == 400 and extra.json() == {"error": "invalid_request"}


def test_invalid_token_and_unknown_origins_fail_without_reflection(tmp_path: Path) -> None:
    with client_for(tmp_path, allowed_origins=("http://localhost:3000",)) as client:
        response = client.post("/api/v1/scans", headers={"Origin": "null", "X-Local-API-Token": TOKEN},
                               json={"target_id": "local-project", "rule_profile_id": "baseline"})
        assert response.status_code == 403
        response = client.post("/api/v1/scans", headers={"X-Local-API-Token": "secret-canary"},
                               json={"target_id": "local-project", "rule_profile_id": "baseline"})
        assert response.status_code == 401
        assert "secret-canary" not in response.text


def test_oversized_scan_body_rejected_before_json_parsing(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        response = client.post("/api/v1/scans", headers={
            "X-Local-API-Token": TOKEN, "Content-Type": "application/json"
        }, content=b" " * 20_000)
    assert response.status_code == 413
    assert response.json() == {"error": "invalid_request"}


def test_target_and_rules_directory_must_not_overlap_or_be_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target"
    rules = target / "rules"
    rules.mkdir(parents=True)
    try:
        ApiSettings(target, rules, TOKEN)
    except ValueError as error:
        assert str(error) == "target_rules_overlap"
    else:
        raise AssertionError("overlapping configuration must fail")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    try:
        ApiSettings(real, link, TOKEN)
    except ValueError as error:
        assert str(error) == "symlink_path_not_allowed"
    else:
        raise AssertionError("symlink configuration must fail")


def test_exact_loopback_origin_cors_preflight_requires_configured_origin(tmp_path: Path) -> None:
    with client_for(tmp_path, allowed_origins=("http://localhost:5173",)) as client:
        response = client.options("/api/v1/scans", headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-local-api-token",
        })
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
        assert "x-local-api-token" in response.headers["access-control-allow-headers"].lower()
        assert response.headers.get("access-control-allow-credentials") is None
        denied = client.options("/api/v1/scans", headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        })
        assert denied.status_code == 403


def test_static_dashboard_optional_serving_has_security_and_no_store_headers(tmp_path: Path) -> None:
    from ai_code_security_analyzer.api.app import create_app

    target = tmp_path / "target"
    rules = tmp_path / "rules"
    target.mkdir()
    rules.mkdir()
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><html><body>dashboard-shell</body></html>")
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",))
    with TestClient(create_app(settings, static_directory=dist)) as client:
        response = client.get("/")
        health = client.get("/api/v1/health")
    assert response.status_code == 200 and "dashboard-shell" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert health.status_code == 200


def _assert_browser_security_headers(response) -> None:
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "default-src 'self'" in response.headers.get("content-security-policy", "")


def test_security_headers_cover_normal_preflight_early_rejections_and_static_assets(tmp_path: Path) -> None:
    from ai_code_security_analyzer.api.app import create_app

    target = tmp_path / "target"
    rules = tmp_path / "rules"
    target.mkdir()
    rules.mkdir()
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><script src='/assets/app.js'></script>")
    (dist / "assets" / "app.js").write_text("const app = true;")
    (dist / "assets" / "app.css").write_text("body { color: black; }")
    settings = ApiSettings(
        target, rules, TOKEN,
        allowed_hosts=("testserver", "127.0.0.1", "localhost"),
        allowed_origins=("http://127.0.0.1:8765",),
    )
    app = create_app(settings, static_directory=dist)
    with TestClient(app, raise_server_exceptions=False) as client:
        responses = [
            client.get("/api/v1/health"),
            client.post("/api/v1/scans", json={"target_id": "local-project", "rule_profile_id": "baseline"}),
            client.get("/api/v1/health", headers={"origin": "https://evil.example"}),
            client.get("/api/v1/health", headers={"host": "evil.example"}),
            client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Content-Type": "text/plain"}, content="{}"),
            client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Content-Type": "application/json"}, content=b"{"),
            client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Content-Type": "application/json"}, content=b" " * 20_000),
        ]
        preflight = client.options("/api/v1/scans", headers={
            "Origin": "http://127.0.0.1:8765",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-local-api-token",
        })
        assets = [client.get("/"), client.get("/assets/app.js"), client.get("/assets/app.css")]
    assert [response.status_code for response in responses] == [200, 401, 403, 400, 415, 400, 413]
    assert preflight.status_code == 200
    assert preflight.headers.get("access-control-allow-origin") == "http://127.0.0.1:8765"
    assert all(response.status_code == 200 for response in assets)
    for response in [*responses, preflight, *assets]:
        _assert_browser_security_headers(response)


def test_rejected_header_matrix_never_calls_scan_service(tmp_path: Path) -> None:
    client = client_for(tmp_path, allowed_origins=("http://127.0.0.1:8765",))
    scan_calls: list[tuple[object, ...]] = []
    client.app.state.scan_service.scan = lambda *args: scan_calls.append(args)
    payload = json.dumps({"target_id": "local-project", "rule_profile_id": "baseline"})
    with client:
        cases = [
            client.post("/api/v1/scans", headers={"X-Local-API-Token": "x" * 257, "Content-Type": "application/json"}, content=payload),
            client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Content-Type": "application/json", "Origin": "http://localhost:8765"}, content=payload),
            client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Content-Type": "application/json", "Origin": "http://127.0.0.1:9999"}, content=payload),
            client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Content-Type": "application/json"}, json={"target_id": "local-project", "rule_profile_id": "baseline", "extra": True}),
        ]
        duplicate_header = client.get("/api/v1/health", headers=[("host", "testserver"), ("host", "evil.example")])
        duplicate_origin = client.get("/api/v1/health", headers=[("host", "testserver"), ("origin", "http://127.0.0.1:8765"), ("origin", "https://evil.example")])
        duplicate_token = client.post("/api/v1/scans", headers=[("host", "testserver"), ("x-local-api-token", TOKEN), ("x-local-api-token", TOKEN), ("content-type", "application/json")], content=payload)
        duplicate_type = client.post("/api/v1/scans", headers=[("host", "testserver"), ("x-local-api-token", TOKEN), ("content-type", "application/json"), ("content-type", "text/plain")], content=payload)
        duplicate_length = client.post("/api/v1/scans", headers=[("host", "testserver"), ("x-local-api-token", TOKEN), ("content-type", "application/json"), ("content-length", str(len(payload))), ("content-length", str(len(payload)))], content=payload)
    assert [response.status_code for response in cases] == [401, 403, 403, 400]
    assert all(response.status_code == 400 for response in [duplicate_header, duplicate_origin, duplicate_token, duplicate_type, duplicate_length])
    assert all("x" * 257 not in response.text and "secret" not in response.text for response in cases)
    assert scan_calls == []


def test_internal_error_is_sanitized_and_keeps_security_headers(tmp_path: Path) -> None:
    from ai_code_security_analyzer.api.app import create_app

    target = tmp_path / "target"
    rules = tmp_path / "rules"
    target.mkdir()
    rules.mkdir()
    app = create_app(ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",)))

    def fail(_target: str, _profile: str):
        raise RuntimeError("PRIVATE_TRACEBACK_CANARY /private/project")

    app.state.scan_service.scan = fail
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN}, json={"target_id": "local-project", "rule_profile_id": "baseline"})
    assert response.status_code == 500
    assert response.json() == {"error": "internal_error"}
    assert "PRIVATE_TRACEBACK_CANARY" not in response.text and "/private/project" not in response.text
    _assert_browser_security_headers(response)
