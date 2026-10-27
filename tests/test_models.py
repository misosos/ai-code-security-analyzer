import json

import pytest
from pydantic import ValidationError

from ai_code_security_analyzer.models import (
    Confirmation,
    ConfirmationMethod,
    Finding,
    FindingStatus,
    Severity,
)


def finding_data() -> dict[str, object]:
    return {
        "finding_id": "finding-1",
        "rule_id": "sample.rule",
        "title": "Sample finding",
        "description": "A synthetic example for contract tests.",
        "severity": "high",
        "source_tool": "sample-scanner",
        "file_path": "src/example.py",
        "line_number": 4,
        "evidence": "synthetic input reaches a sensitive operation",
        "cwe": "CWE-89",
        "recommendation": "Validate the input before use.",
    }


def test_valid_finding_defaults_to_unverified() -> None:
    finding = Finding.model_validate(finding_data())

    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.line_number == 4


@pytest.mark.parametrize("missing", ["finding_id", "rule_id", "title", "description", "severity", "source_tool", "file_path", "evidence"])
def test_required_fields(missing: str) -> None:
    data = finding_data()
    del data[missing]

    with pytest.raises(ValidationError):
        Finding.model_validate(data)


@pytest.mark.parametrize("field,value", [("severity", "urgent"), ("status", "accepted")])
def test_unknown_enum_values_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding_data(), field: value})


def test_tool_warning_cannot_be_confirmed_without_independent_evidence() -> None:
    with pytest.raises(ValidationError, match="independent confirmation"):
        Finding.model_validate({**finding_data(), "status": "confirmed"})


def test_confirmed_finding_requires_structured_confirmation() -> None:
    finding = Finding.model_validate(
        {
            **finding_data(),
            "status": "confirmed",
            "confirmation": {
                "method": "manual_review",
                "summary": "Reviewed the complete synthetic data flow.",
            },
        }
    )

    assert finding.confirmation == Confirmation(
        method=ConfirmationMethod.MANUAL_REVIEW,
        summary="Reviewed the complete synthetic data flow.",
    )
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_json_round_trip_uses_string_enums_and_explicit_nulls() -> None:
    original = Finding.model_validate(finding_data())
    payload = original.model_dump_json()
    serialized = json.loads(payload)

    assert serialized["severity"] == "high"
    assert serialized["status"] == "unverified"
    assert serialized["confirmation"] is None
    assert Finding.model_validate_json(payload) == original


@pytest.mark.parametrize("field,value", [("line_number", 0), ("line_number", "4"), ("cwe", "89"), ("title", "  ")])
def test_invalid_field_constraints(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding_data(), field: value})
