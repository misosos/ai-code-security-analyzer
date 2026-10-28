from __future__ import annotations

import threading
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _finding_id
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService, ServiceError


TOKEN = "z" * 48


def _finding(index: int = 1) -> Finding:
    path = f"src/file{index}.js"
    finding_id = _finding_id("javascript.test", path, index, 1, index, 10)
    return Finding(
        finding_id=finding_id, rule_id="javascript.test", title="synthetic title",
        description="secret-canary-description", severity=Severity.HIGH,
        status=FindingStatus.UNVERIFIED, source_tool="semgrep", file_path=path,
        line_number=index, evidence="secret-canary-code", cwe="CWE-78",
    )


class FakeAdapter:
    def __init__(self, _rules: Path, result=None, started=None, release=None):
        self.result = result or ScanResult(ScanStatus.COMPLETED, (_finding(),), (), 0, "1.182.1")
        self.started = started
        self.release = release
        self.seen = None

    def _scan_with_evidence(self, target: Path, rules_file: Path):
        from types import SimpleNamespace
        self.seen = (target, rules_file)
        if self.started:
            self.started.set()
            self.release.wait(timeout=3)
        return SimpleNamespace(result=self.result, taint_evidence=())


def _client(tmp_path: Path, adapter_factory=FakeAdapter):
    target = tmp_path / "project"
    rules = tmp_path / "rules"
    target.mkdir(parents=True, exist_ok=True)
    rules.mkdir(exist_ok=True)
    (rules / "security-baseline.yml").write_text("rules: []\n")
    (rules / "experimental").mkdir(exist_ok=True)
    (rules / "experimental" / "javascript-eval-taint.yml").write_text("rules: []\n")
    (rules / "experimental" / "javascript-command-injection-taint.yml").write_text("rules: []\n")
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver", "localhost", "127.0.0.1"))
    service = ScanService(settings, adapter_factory=adapter_factory)
    return TestClient(create_app(settings, scan_service=service)), service


def _request(client, profile="baseline", target="local-project"):
    return client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN}, json={
        "target_id": target, "rule_profile_id": profile,
    })


def test_scan_uses_allowlisted_paths_and_returns_consumer_claims_only(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    with client:
        response = _request(client)
    assert response.status_code == 200
    payload = response.json()
    assert payload["scan_status"] == "completed" and payload["completed"] is True
    assert payload["finding_count"] == payload["displayed_finding_count"] == 1
    item = payload["findings"][0]
    assert item["finding_kind"] == "pattern"
    assert item["verification_status"] == "unverified"
    assert item["evidence_validation_status"] == "validated"
    assert "match_reported" in item["supported_claims"]
    assert "vulnerability_confirmed" not in item["supported_claims"]
    assert str(tmp_path) not in response.text
    assert "secret-canary" not in response.text
    target, rules_file = service.settings.target_directory, service.settings.trusted_rules_directory / "security-baseline.yml"
    assert target.is_dir() and rules_file.is_file()


def test_invalid_ids_and_failed_scan_do_not_return_supported_claims(tmp_path: Path) -> None:
    client, _ = _client(tmp_path, lambda rules: FakeAdapter(
        rules, ScanResult(ScanStatus.TIMED_OUT, (_finding(),), ("semgrep_timeout",), None, None)
    ))
    with client:
        assert _request(client, target="../../etc").json() == {"error": "target_not_allowed"}
        assert _request(client, profile="/etc/passwd").json() == {"error": "rule_profile_not_allowed"}
        response = _request(client)
    assert response.status_code == 200
    payload = response.json()
    assert payload["scan_status"] == "timed_out" and payload["completed"] is False
    assert payload["findings"][0]["supported_claims"] == []
    assert payload["findings"][0]["evidence_validation_status"] == "rejected"
    assert "scan_failed" in payload["limitations"]


@pytest.mark.parametrize("status", [
    ScanStatus.EXECUTION_FAILED,
    ScanStatus.INVALID_JSON,
    ScanStatus.OUTPUT_LIMIT_EXCEEDED,
    ScanStatus.NOT_INSTALLED,
])
def test_each_terminal_scan_failure_exposes_no_supported_claims(tmp_path: Path, status) -> None:
    failed = ScanResult(status, (_finding(),), ("private-diagnostic",), None, None)
    client, _ = _client(tmp_path, lambda rules: FakeAdapter(rules, failed))
    with client:
        payload = _request(client).json()
    assert payload["scan_status"] == status.value
    assert payload["completed"] is False
    assert payload["findings"][0]["supported_claims"] == []
    assert payload["findings"][0]["evidence_validation_status"] == "rejected"
    assert "private-diagnostic" not in str(payload)


def test_partial_zero_findings_and_omission_are_explicit(tmp_path: Path) -> None:
    partial = ScanResult(ScanStatus.PARTIAL, (), ("result_limit",), 0, "1.182.1")
    client, _ = _client(tmp_path, lambda rules: FakeAdapter(rules, partial))
    with client:
        result = _request(client).json()
    assert result["completed"] is False
    assert result["finding_count"] == 0
    assert "scan_partial" in result["limitations"]
    assert "finding_count_not_confirmed_vulnerability_count" in result["limitations"]

    many = ScanResult(ScanStatus.COMPLETED, tuple(_finding(i) for i in range(1, 53)), (), 0, "1.182.1")
    client, _ = _client(tmp_path / "many", lambda rules: FakeAdapter(rules, many))
    with client:
        result = _request(client).json()
    assert result["finding_count"] == 52
    assert result["displayed_finding_count"] == 50
    assert result["omitted_finding_count"] == 2
    assert "omitted_findings_not_individually_validated" in result["limitations"]


def test_scan_lock_rejects_second_run_and_releases_after_completion(tmp_path: Path) -> None:
    started, release = threading.Event(), threading.Event()
    client, service = _client(tmp_path, lambda rules: FakeAdapter(rules, started=started, release=release))
    first_result = []

    def scan_first():
        first_result.append(_request(client))

    with client:
        thread = threading.Thread(target=scan_first)
        thread.start()
        try:
            assert started.wait(timeout=2)
            second = _request(client)
        finally:
            release.set()
        thread.join(timeout=3)
    assert not thread.is_alive() and len(first_result) == 1
    assert second.status_code == 409 and second.json() == {"error": "scan_already_running"}
    assert first_result[0].status_code == 200
    result = service.scan("local-project", "baseline")
    assert result.scan_status is ScanStatus.COMPLETED


def test_consumer_failure_is_fail_closed(tmp_path: Path, monkeypatch) -> None:
    import ai_code_security_analyzer.services.scan_service as module

    def reject(*_args, **_kwargs):
        raise ValueError("private diagnostic")

    monkeypatch.setattr(module, "build_evidence_summary", reject)
    client, _ = _client(tmp_path)
    with client:
        response = _request(client)
    item = response.json()["findings"][0]
    assert item["supported_claims"] == []
    assert item["validation_error_code"] == "evidence_validation_failed"
    assert "private diagnostic" not in response.text


def test_target_replacement_with_symlink_is_rejected_before_adapter(tmp_path: Path) -> None:
    client, service = _client(tmp_path)
    target = service.settings.target_directory
    moved = tmp_path / "original-project"
    target.rename(moved)
    outside = tmp_path / "outside"
    outside.mkdir()
    target.symlink_to(outside, target_is_directory=True)
    try:
        service.scan("local-project", "baseline")
    except ServiceError as error:
        assert error.code == "target_not_allowed"
    else:
        raise AssertionError("changed target path must fail closed")
