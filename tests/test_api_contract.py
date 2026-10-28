from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai_code_security_analyzer.api.schemas import ApiFinding, ScanRequest, ScanResponse
from ai_code_security_analyzer.evidence_sufficiency import ClaimType


def test_scan_request_is_closed_and_never_accepts_paths() -> None:
    with pytest.raises(ValidationError):
        ScanRequest.model_validate({
            "target_id": "local-project", "rule_profile_id": "baseline", "path": "/tmp/private"
        })


def test_api_finding_dto_rejects_unsafe_paths_and_identifiers() -> None:
    common = {
        "finding_id": "semgrep:" + "a" * 24,
        "rule_id": "baseline.javascript.test",
        "severity": "high",
        "finding_kind": "pattern",
        "evidence_validation_status": "validated",
        "supported_claims": [ClaimType.MATCH_REPORTED.value],
        "restricted_claims": [],
    }
    for unsafe in ("/etc/passwd", "../secrets", "a/../../b", "file:///tmp/x", "a\nb"):
        with pytest.raises(ValidationError):
            ApiFinding.model_validate({**common, "file_path": unsafe})
    with pytest.raises(ValidationError):
        ApiFinding.model_validate({**common, "finding_id": "../../secret"})


def test_api_schema_does_not_allow_public_finding_fields() -> None:
    schema = ScanResponse.model_json_schema()
    properties = schema["$defs"]["ApiFinding"]["properties"]
    assert "description" not in properties
    assert "evidence" not in properties
    assert "confirmation" not in properties
    assert "absolute_path" not in properties
