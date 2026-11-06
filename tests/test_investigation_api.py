from __future__ import annotations

import os
import shutil
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.services.scan_service import ApiSettings
from ai_code_security_analyzer.services.scan_service import ScanService
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.rule_bytes_identity import (
    RULE_BYTES_INVOCATION_ID, RULE_BYTES_OBSERVATION_VERSION, RuleBytesObservation,
)
from test_finding_disappearance_evaluator import bundle, finding


TOKEN = "t" * 48
HEADERS = {"X-Local-API-Token": TOKEN}


class SequenceScanService:
    def __init__(self, runs):
        self.runs = iter(runs)
        self.calls = 0

    def _scan_with_manifest(self, target_id: str, rule_profile_id: str, *, investigation_verbose: bool = False):
        assert investigation_verbose is True
        self.calls += 1
        run = next(self.runs)
        assert run.manifest.target_id == target_id
        assert run.manifest.rule_profile_id == rule_profile_id
        return run.response, run.manifest

    def _scan_with_rule_bytes_manifest(self, target_id: str, rule_profile_id: str):
        self.calls += 1
        run = next(self.runs)
        assert run.manifest.target_id == target_id
        assert run.manifest.rule_profile_id == rule_profile_id
        observation = RuleBytesObservation(
            RULE_BYTES_OBSERVATION_VERSION, run.manifest.scan_ref, target_id, rule_profile_id,
            RULE_BYTES_INVOCATION_ID, run.manifest.semgrep_version, b"r" * 32,
        )
        return run.response, run.manifest, observation


def app_for(tmp_path: Path, runs=(), *, enabled=True, origins=()):
    target, rules = tmp_path / "target", tmp_path / "rules"
    target.mkdir(exist_ok=True, parents=True)
    rules.mkdir(exist_ok=True, parents=True)
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",), allowed_origins=origins)
    service = SequenceScanService(runs)
    app = create_app(settings, scan_service=service, investigation_api_enabled=enabled)
    return app, service


def test_http_api_scans_registers_compares_and_releases_without_disclosing_internal_evidence(tmp_path: Path):
    baseline = bundle(finding("a"), finding("b", "src/b.js"), target="local-project")
    current = bundle(finding("a"), finding("c", "src/c.js"), target="local-project")
    app, service = app_for(tmp_path, (baseline, current))
    with TestClient(app) as client:
        first = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        second = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert first.status_code == second.status_code == 200
        a, b = first.json(), second.json()
        assert a["contract_version"] == "investigation-scan/v1"
        assert a["run_handle"] != b["run_handle"]
        assert set(a) == {"contract_version", "run_handle", "scan"}
        assert "findings" in a["scan"] and "scan_ref" not in a["scan"]
        assert "manifest" not in first.text and "source_snapshot" not in first.text
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": a["run_handle"], "current_handle": b["run_handle"],
        })
        assert session.status_code == 201
        handle = session.json()["investigation_handle"]
        evaluation = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": handle,
        })
        assert evaluation.status_code == 200
        result = evaluation.json()
        assert result["overall_assessment"] == "UNDETERMINED"
        assert [(item["category"], item["finding_id"]) for item in result["findings"]] == [
            ("shared", finding("a").finding_id),
            ("currentOnly", finding("c").finding_id),
            ("baselineOnly", finding("b").finding_id),
        ]
        assert "source code" not in evaluation.text.lower()
        blocked_release = client.post("/api/v2/investigation-release", headers=HEADERS, json={
            "kind": "run", "handle": a["run_handle"],
        })
        assert blocked_release.status_code == 409
        assert blocked_release.json() == {"error": "binding_rejected"}
        assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
            "kind": "investigation", "handle": handle,
        }).status_code == 204
        assert client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": handle,
        }).status_code == 404
        for run_handle in (a["run_handle"], b["run_handle"]):
            assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
                "kind": "run", "handle": run_handle,
            }).status_code == 204
            assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
                "kind": "run", "handle": run_handle,
            }).status_code == 204
    assert service.calls == 2
    assert app.state.investigation_registry.active_run_count == 0
    assert app.state.investigation_registry.active_session_count == 0


def test_rule_bytes_opt_in_api_returns_only_closed_equality_projection(tmp_path: Path):
    baseline = bundle(finding("a"), target="local-project", invocation=RULE_BYTES_INVOCATION_ID)
    current = bundle(finding("b"), target="local-project", invocation=RULE_BYTES_INVOCATION_ID)
    app, service = app_for(tmp_path, (baseline, current))
    with TestClient(app) as client:
        runs = [client.post("/api/v2/investigation-scans/rule-bytes", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        }) for _ in range(2)]
        assert [item.status_code for item in runs] == [200, 200]
        assert all("digest" not in item.text.lower() and "rule_bytes" not in item.text.lower() for item in runs)
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": runs[0].json()["run_handle"],
            "current_handle": runs[1].json()["run_handle"],
        })
        result = client.post("/api/v2/investigations/rule-bytes/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })
        assert result.status_code == 200
        assert result.json() == {
            "contract_version": "rule-bytes-comparison/v1",
            "status": "SAME_SELECTED_BYTES",
            "limitation_codes": ["selected_rule_bytes_only", "loaded_rule_identity_unverified"],
        }
        assert "sha" not in result.text.lower() and "digest" not in result.text.lower()
    assert service.calls == 2


@pytest.mark.parametrize("change_comment,expected", [
    (False, "SAME_SELECTED_BYTES"),
    (True, "DIFFERENT_SELECTED_BYTES"),
])
def test_real_semgrep_rule_bytes_api_binds_the_same_execution(
    tmp_path: Path, change_comment: bool, expected: str,
) -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("required_semgrep_unavailable")
        pytest.skip("Semgrep is not installed")
    target, rules = tmp_path / "target", tmp_path / "rules"
    target.mkdir(); rules.mkdir()
    (target / "app.js").write_text('eval("synthetic");\n', encoding="utf-8")
    source_rule = Path(__file__).parents[1] / "rules" / "security-baseline.yml"
    rule = rules / "security-baseline.yml"
    shutil.copyfile(source_rule, rule)
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",))
    app = create_app(settings, investigation_api_enabled=True)
    app.state.investigation_rate_limiter._limits = {
        **app.state.investigation_rate_limiter._limits, "scan": (4, 60.0),
    }
    with TestClient(app) as client:
        def scan_once():
            return client.post("/api/v2/investigation-scans/rule-bytes", headers=HEADERS, json={
                "target_id": "local-project", "rule_profile_id": "baseline",
            })
        first = scan_once()
        if change_comment:
            rule.write_bytes(rule.read_bytes() + b"\n# ER-D7 synthetic comment-only change\n")
        second = scan_once()
        assert first.status_code == second.status_code == 200
        assert first.json()["scan"]["completed"] is True
        assert second.json()["scan"]["completed"] is True
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": first.json()["run_handle"],
            "current_handle": second.json()["run_handle"],
        })
        result = client.post("/api/v2/investigations/rule-bytes/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })
        assert result.status_code == 200
        assert result.json()["status"] == expected
        assert "digest" not in result.text.lower() and "sha256" not in result.text.lower()


def test_real_semgrep_rule_bytes_partial_skip_is_unverified(tmp_path: Path) -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("Semgrep is not installed")
    target, rules = tmp_path / "target", tmp_path / "rules"
    target.mkdir(); rules.mkdir()
    (target / "stable.js").write_text('eval("stable");\n', encoding="utf-8")
    (target / "retired.js").write_text('eval("retired");\n', encoding="utf-8")
    shutil.copyfile(Path(__file__).parents[1] / "rules" / "security-baseline.yml", rules / "security-baseline.yml")
    app = create_app(ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",)), investigation_api_enabled=True)
    app.state.investigation_rate_limiter._limits = {**app.state.investigation_rate_limiter._limits, "scan": (4, 60.0)}
    with TestClient(app) as client:
        first = client.post("/api/v2/investigation-scans/rule-bytes", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        (target / ".semgrepignore").write_text("retired.js\n", encoding="utf-8")
        second = client.post("/api/v2/investigation-scans/rule-bytes", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert first.status_code == second.status_code == 200
        assert second.json()["scan"]["scan_status"] == "partial"
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": first.json()["run_handle"], "current_handle": second.json()["run_handle"],
        })
        equality = client.post("/api/v2/investigations/rule-bytes/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })
        assert equality.status_code == 200
        assert equality.json()["status"] == "UNVERIFIED"
        finding_evaluation = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })
        assert finding_evaluation.status_code == 200
        assert finding_evaluation.json()["overall_assessment"] == "INCOMPARABLE"


def test_investigation_http_auth_closed_inputs_and_security_headers(tmp_path: Path):
    run = bundle(target="local-project")
    app, service = app_for(tmp_path, (run,))
    with TestClient(app) as client:
        path = "/api/v2/investigation-scans"
        data = {"target_id": "local-project", "rule_profile_id": "baseline"}
        assert client.post(path, json=data).status_code == 401
        assert client.post(path, headers={**HEADERS, "X-Local-API-Token": "x"}, json=data).status_code == 401
        duplicate_token = client.post(path, headers=[("X-Local-API-Token", TOKEN), ("X-Local-API-Token", TOKEN)], json=data)
        assert duplicate_token.status_code == 400
        assert client.post(path, headers={**HEADERS, "Host": "attacker.test"}, json=data).status_code == 400
        assert client.post(path, headers={**HEADERS, "Origin": "https://attacker.test"}, json=data).status_code == 403
        wrong_type = client.post(path, headers={**HEADERS, "Content-Type": "text/plain"}, content=b"{}")
        assert wrong_type.status_code == 415
        extra = client.post(path, headers=HEADERS, json={**data, "unexpected": True})
        assert extra.status_code == 400
        nan = client.post(path, headers={**HEADERS, "Content-Type": "application/json"}, content=b'{"target_id":"a","rule_profile_id":NaN}')
        assert nan.status_code == 400
        invalid_utf8 = client.post(path, headers={**HEADERS, "Content-Type": "application/json"}, content=b'{"target_id":"\xff","rule_profile_id":"baseline"}')
        assert invalid_utf8.status_code == 400
        control = client.post(path, headers={**HEADERS, "Content-Type": "application/json"}, content=b'{"target_id":"bad\\u0001id","rule_profile_id":"baseline"}')
        assert control.status_code == 400
        wrong_type_value = client.post(path, headers=HEADERS, json={"target_id": True, "rule_profile_id": "baseline"})
        assert wrong_type_value.status_code == 400
        too_large = client.post(path, headers={**HEADERS, "Content-Type": "application/json"}, content=b" " * 16_385)
        assert too_large.status_code == 413
        good = client.post(path, headers=HEADERS, json=data)
        assert good.status_code == 200
        assert good.headers["cache-control"] == "no-store"
        assert good.headers["referrer-policy"] == "no-referrer"
    assert service.calls == 1


def test_investigation_unsupported_routes_are_not_token_bypass_and_disabled_api_is_explicit(tmp_path: Path):
    app, _ = app_for(tmp_path, enabled=False)
    with TestClient(app) as client:
        no_token = client.post("/api/v2/not-a-route", content=b"{}")
        unsupported = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        get_missing = client.get("/api/v2/not-a-route", headers=HEADERS)
    assert no_token.status_code == 401
    assert unsupported.status_code == 503 and unsupported.json() == {"error": "unsupported_deployment"}
    assert get_missing.status_code == 404


def test_api_instances_have_independent_investigation_registries(tmp_path: Path):
    run_a = bundle(target="local-project")
    run_b = bundle(target="local-project")
    app_a, _ = app_for(tmp_path / "a", (run_a,))
    app_b, _ = app_for(tmp_path / "b", (run_b,))
    with TestClient(app_a) as first, TestClient(app_b) as second:
        response = first.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        handle = response.json()["run_handle"]
        missing = second.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": handle, "current_handle": handle,
        })
    assert missing.status_code == 404


def test_run_capacity_rejects_before_an_extra_scan_is_started(tmp_path: Path):
    runs = tuple(bundle(finding(char), target="local-project") for char in "abcd")
    app, service = app_for(tmp_path, runs)
    app.state.investigation_rate_limiter._limits = {
        **app.state.investigation_rate_limiter._limits, "scan": (5, 60.0),
    }
    with TestClient(app) as client:
        handles = []
        for _ in range(4):
            response = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
                "target_id": "local-project", "rule_profile_id": "baseline",
            })
            assert response.status_code == 200
            handles.append(response.json()["run_handle"])
        denied = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert denied.status_code == 429 and denied.json() == {"error": "resource_limit"}
        for handle in handles:
            client.post("/api/v2/investigation-release", headers=HEADERS, json={"kind": "run", "handle": handle})
    assert service.calls == 4


def test_cors_preflight_is_exact_and_read_only(tmp_path: Path):
    app, _ = app_for(tmp_path, origins=("http://localhost:5173",))
    with TestClient(app) as client:
        registry = app.state.investigation_registry
        before = (registry.active_run_count, registry.active_session_count, registry.stored_bytes)
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-local-api-token",
        }
        accepted = client.options("/api/v2/investigations/evaluate", headers=headers)
        rejected = client.options("/api/v2/investigations/evaluate", headers={
            **headers, "Access-Control-Request-Headers": "content-type,authorization",
        })
        forged = client.options("/api/v2/investigations/evaluate", headers={
            **headers, "Origin": "https://evil.example",
        })
        after = (registry.active_run_count, registry.active_session_count, registry.stored_bytes)
    assert accepted.status_code == 200
    assert accepted.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert accepted.headers.get("access-control-allow-credentials") is None
    assert rejected.status_code == 400 and forged.status_code == 403
    assert before == after == (0, 0, 0)


def test_client_disconnect_during_response_releases_new_run(tmp_path: Path):
    run = bundle(target="local-project")
    app, _ = app_for(tmp_path, (run,))
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/api/v2/investigation-scans", "raw_path": b"/api/v2/investigation-scans",
        "query_string": b"", "root_path": "", "headers": [
            (b"host", b"testserver"), (b"x-local-api-token", TOKEN.encode()),
            (b"content-type", b"application/json"),
            (b"content-length", b"58"),
        ], "client": ("127.0.0.1", 12345), "server": ("testserver", 80), "state": {},
    }
    request_body = json.dumps({"target_id": "local-project", "rule_profile_id": "baseline"}).encode()
    scope["headers"][-1] = (b"content-length", str(len(request_body)).encode())
    messages = [{"type": "http.request", "body": request_body, "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.body":
            raise OSError("synthetic disconnect")

    async def invoke():
        try:
            await app(scope, receive, send)
        except OSError:
            pass

    asyncio.run(invoke())
    assert app.state.investigation_registry.active_run_count == 0


def test_client_disconnect_during_session_response_releases_session(tmp_path: Path):
    app, _ = app_for(tmp_path)
    registry = app.state.investigation_registry
    first = bundle(finding("a"), target="local-project")
    second = bundle(finding("b"), target="local-project")
    handles = [registry.register_run(run.response, run.manifest) for run in (first, second)]
    body = json.dumps({"baseline_handle": handles[0], "current_handle": handles[1]}).encode()
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/api/v2/investigations", "raw_path": b"/api/v2/investigations",
        "query_string": b"", "root_path": "", "headers": [
            (b"host", b"testserver"), (b"x-local-api-token", TOKEN.encode()),
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
        ], "client": ("127.0.0.1", 12345), "server": ("testserver", 80), "state": {},
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.body":
            raise OSError("synthetic disconnect")

    async def invoke():
        try:
            await app(scope, receive, send)
        except OSError:
            pass

    asyncio.run(invoke())
    assert registry.active_session_count == 0
    assert registry.active_run_count == 2


def test_expired_run_and_session_are_not_returned_as_empty_evaluations(tmp_path: Path):
    first, second = bundle(finding("a"), target="local-project"), bundle(finding("b"), target="local-project")
    app, _ = app_for(tmp_path, (first, second))
    now = [0.0]
    app.state.investigation_registry._clock = lambda: now[0]
    with TestClient(app) as client:
        handles = []
        for _ in range(2):
            response = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
                "target_id": "local-project", "rule_profile_id": "baseline",
            })
            assert response.status_code == 200
            handles.append(response.json()["run_handle"])
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": handles[0], "current_handle": handles[1],
        })
        assert session.status_code == 201
        now[0] = 901.0
        expired = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })
    assert expired.status_code == 404
    assert expired.json() == {"error": "evidence_unavailable"}
    assert "findings" not in expired.json()


def test_http_evaluation_is_single_flight_and_busy_is_not_an_empty_result(tmp_path: Path):
    first, second = bundle(finding("a"), target="local-project"), bundle(finding("b"), target="local-project")
    app, _ = app_for(tmp_path, (first, second))
    entered, continue_evaluation = threading.Event(), threading.Event()
    app.state.investigation_registry._evaluation_hook = lambda: (entered.set(), continue_evaluation.wait(5))
    with TestClient(app) as client:
        handles = [client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        }).json()["run_handle"] for _ in range(2)]
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": handles[0], "current_handle": handles[1],
        }).json()["investigation_handle"]
        payload = {"investigation_handle": session}
        with ThreadPoolExecutor(max_workers=1) as pool:
            first_result = pool.submit(client.post, "/api/v2/investigations/evaluate", headers=HEADERS, json=payload)
            assert entered.wait(2)
            busy = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json=payload)
            continue_evaluation.set()
            completed = first_result.result(timeout=5)
    assert busy.status_code == 409 and busy.json() == {"error": "evaluation_busy"}
    assert completed.status_code == 200 and "findings" in completed.json()


def test_app_rate_limiter_is_bounded_and_thread_safe():
    from ai_code_security_analyzer.api.routes import AppRateLimiter

    now = [0.0]
    limiter = AppRateLimiter(clock=lambda: now[0])
    accepted: list[bool] = []
    lock = threading.Lock()

    def attempt():
        result = limiter.allow("session")
        with lock:
            accepted.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(40)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert sum(accepted) == 10
    now[0] = 60.0
    assert limiter.allow("session") is True


def test_real_http_semgrep_ab_to_ac_investigation_flow(tmp_path: Path):
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            raise AssertionError("Semgrep is required for this integration job")
        import pytest
        pytest.skip("Semgrep CLI is not installed")
    target = tmp_path / "project"
    rules = Path(__file__).parents[1] / "rules"
    target.mkdir()
    (target / "stable.js").write_text("const input = '2 + 2';\neval(input);\n", encoding="utf-8")
    (target / "firestore.rules").write_text(
        "service cloud.firestore {\n match /databases/{database}/documents {\n"
        " allow write: if true;\n }\n}\n", encoding="utf-8",
    )
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",))
    service = ScanService(settings)
    app = create_app(settings, scan_service=service, investigation_api_enabled=True)
    with TestClient(app) as client:
        first = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert first.status_code == 200, first.text
        baseline = first.json()
        assert baseline["scan"]["scan_status"] == ScanStatus.COMPLETED.value
        assert {item["rule_id"] for item in baseline["scan"]["findings"]} >= {
            "baseline.javascript-dynamic-eval", "baseline.firestore-unconditional-write",
        }
        (target / "firestore.rules").unlink()
        (target / "new.jsx").write_text(
            "const node = <div dangerouslySetInnerHTML={{__html: input}} />;\n", encoding="utf-8",
        )
        second = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert second.status_code == 200, second.text
        current = second.json()
        assert {item["rule_id"] for item in current["scan"]["findings"]} >= {
            "baseline.javascript-dynamic-eval", "baseline.react-dangerous-html",
        }
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": baseline["run_handle"], "current_handle": current["run_handle"],
        })
        assert session.status_code == 201, session.text
        investigation_handle = session.json()["investigation_handle"]
        evaluation = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": investigation_handle,
        })
        assert evaluation.status_code == 200, evaluation.text
        assert evaluation.json()["overall_assessment"] == "UNDETERMINED"
        by_id = {item["finding_id"]: item["category"] for item in evaluation.json()["findings"]}
        baseline_ids = {item["rule_id"]: item["finding_id"] for item in baseline["scan"]["findings"]}
        current_ids = {item["rule_id"]: item["finding_id"] for item in current["scan"]["findings"]}
        assert by_id[baseline_ids["baseline.javascript-dynamic-eval"]] == "shared"
        assert by_id[baseline_ids["baseline.firestore-unconditional-write"]] == "baselineOnly"
        assert by_id[current_ids["baseline.react-dangerous-html"]] == "currentOnly"
        assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
            "kind": "investigation", "handle": investigation_handle,
        }).status_code == 204
        assert client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": investigation_handle,
        }).status_code == 404


def test_real_http_semgrep_verbose_skip_evidence_preserves_partial_and_incomparable(tmp_path: Path):
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            raise AssertionError("Semgrep is required for this integration job")
        import pytest
        pytest.skip("Semgrep CLI is not installed")
    target = tmp_path / "project"
    rules = Path(__file__).parents[1] / "rules"
    target.mkdir()
    (target / "stable.js").write_text("function stable(input) { return eval(input); }\n", encoding="utf-8")
    (target / "retired.js").write_text("function retired(input) { return eval(input); }\n", encoding="utf-8")
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",))
    service = ScanService(settings)
    app = create_app(settings, scan_service=service, investigation_api_enabled=True)
    with TestClient(app) as client:
        first = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert first.status_code == 200, first.text
        baseline = first.json()
        assert baseline["scan"]["scan_status"] == "completed"
        baseline_findings = {item["file_path"]: item["finding_id"] for item in baseline["scan"]["findings"]}
        assert set(baseline_findings) == {"stable.js", "retired.js"}

        (target / ".semgrepignore").write_text("retired.js\n", encoding="utf-8")
        second = client.post("/api/v2/investigation-scans", headers=HEADERS, json={
            "target_id": "local-project", "rule_profile_id": "baseline",
        })
        assert second.status_code == 200, second.text
        current = second.json()
        assert current["run_handle"] != baseline["run_handle"]
        assert current["scan"]["scan_status"] == "partial"
        assert current["scan"]["completed"] is False
        assert {item["file_path"] for item in current["scan"]["findings"]} == {"stable.js"}
        current_run = app.state.investigation_registry.get_run(current["run_handle"])
        scope = current_run.manifest.scope_evidence
        assert current_run.manifest.execution_evidence.invocation_id == "semgrep-json-investigation-verbose-v1"
        assert scope.completeness_status.value == "UNVERIFIED"
        assert scope.skipped_status.value == "OBSERVED"
        assert [(item.path, item.reason_code) for item in scope.skipped_paths] == [
            ("retired.js", "semgrepignore_patterns_match"),
        ]

        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": baseline["run_handle"], "current_handle": current["run_handle"],
        })
        assert session.status_code == 201, session.text
        investigation_handle = session.json()["investigation_handle"]
        evaluation_response = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": investigation_handle,
        })
        assert evaluation_response.status_code == 200, evaluation_response.text
        evaluation = evaluation_response.json()
        assert evaluation["comparability"] == "INCOMPARABLE"
        assert evaluation["overall_assessment"] == "INCOMPARABLE"
        retired = next(item for item in evaluation["findings"] if item["finding_id"] == baseline_findings["retired.js"])
        assert retired["category"] == "baselineOnly"
        assert retired["path_observation"] == "PATH_EXPLICITLY_SKIPPED"
        assert retired["skip_hypothesis"] == "SUPPORTED"
        assert "source_snapshot_not_collected" in evaluation["limitation_codes"]
        assert "scope_completeness_unverified" in evaluation["limitation_codes"]
        assert "retired(input)" not in evaluation_response.text
        assert "paths" not in evaluation_response.text

        assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
            "kind": "investigation", "handle": investigation_handle,
        }).status_code == 204
        assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
            "kind": "run", "handle": baseline["run_handle"],
        }).status_code == 204
        assert client.post("/api/v2/investigation-release", headers=HEADERS, json={
            "kind": "run", "handle": current["run_handle"],
        }).status_code == 204
        assert client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": investigation_handle,
        }).status_code == 404
