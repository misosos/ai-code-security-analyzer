"""Required HTTP-to-Semgrep integration on synthetic source only."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.evidence_sufficiency import ClaimType
from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.services.scan_service import ApiSettings


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-test-token-" + "x" * 40
CANARY = "SYNTHETIC_API_CANARY_MUST_NOT_LEAK"


def test_api_runs_real_semgrep_and_returns_only_validated_claim_codes(tmp_path: Path) -> None:
    executable = shutil.which("semgrep")
    if executable is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    target = tmp_path / "synthetic-project"
    target.mkdir()
    (target / "sample.js").write_text(
        "function handle(req) {\n"
        f"  const marker = '{CANARY}';\n"
        "  eval(req.query.code);\n"
        "  const cp = require('child_process');\n"
        "  cp.exec(req.query.cmd);\n"
        "}\n",
        encoding="utf-8",
    )
    settings = ApiSettings(
        target_directory=target,
        trusted_rules_directory=ROOT / "rules",
        api_token=TOKEN,
        allowed_hosts=("testserver", "127.0.0.1", "localhost"),
    )
    with TestClient(create_app(settings)) as client:
        options = client.get("/api/v1/options").json()
        assert str(ROOT) not in str(options)
        expected_rules = {
            "baseline": {"baseline.javascript-dynamic-eval"},
            "eval-experimental": {
                "experimental.javascript-eval-taint",
                "experimental.javascript-eval-taint-with-synthetic-sanitizer",
            },
            "command-injection-experimental": {"experimental.javascript-command-injection-taint"},
        }
        for profile in expected_rules:
            response = client.post(
                "/api/v1/scans",
                headers={"X-Local-API-Token": TOKEN},
                json={"target_id": "local-project", "rule_profile_id": profile},
            )
            assert response.status_code == 200, response.text
            payload = response.json()
            assert payload["scan_status"] == ScanStatus.COMPLETED.value
            assert payload["semgrep_version"] == "1.182.1"
            assert payload["completed"] is True
            assert payload["finding_count"] >= 1
            assert CANARY not in response.text
            assert str(ROOT) not in response.text
            assert "stderr" not in response.text.lower()
            for item in payload["findings"]:
                assert item["rule_id"] in expected_rules[profile]
                assert item["verification_status"] == FindingStatus.UNVERIFIED.value
                assert "vulnerability_confirmed" not in item["supported_claims"]
                assert item["file_path"] == "sample.js"
                if profile == "command-injection-experimental":
                    assert item["finding_kind"] == "taint"
                    assert item["severity"] == "high"
                    assert set(item["supported_claims"]) == {
                        ClaimType.MATCH_REPORTED.value,
                        ClaimType.TAINT_RULE_MATCH_REPORTED.value,
                        ClaimType.SOURCE_PATTERN_DECLARED.value,
                        ClaimType.SINK_PATTERN_DECLARED.value,
                        ClaimType.MATCH_LOCATION_OBSERVED.value,
                    }
                    assert item["line_number"] == 5
                    restricted = {claim["claim_type"] for claim in item["restricted_claims"]}
                    assert ClaimType.SOURCE_LOCATION_IDENTIFIED.value in restricted
                    assert ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED.value in restricted
                    assert ClaimType.FLOW_TRACE_AVAILABLE.value in restricted
                if profile == "baseline":
                    assert item["finding_kind"] == "pattern"
                if profile == "eval-experimental":
                    assert item["finding_kind"] == "taint"
