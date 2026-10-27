"""Validated, tool-independent security finding data contracts."""

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    """Estimated impact or priority; independent of verification status."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Outcome of human or reproducible verification."""

    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class ConfirmationMethod(StrEnum):
    MANUAL_REVIEW = "manual_review"
    SAFE_REPRODUCTION = "safe_reproduction"


class Confirmation(BaseModel):
    """Evidence that supports a confirmed finding beyond a tool warning."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    method: ConfirmationMethod
    summary: str = Field(min_length=1, strict=True)


class Finding(BaseModel):
    """A single finding, with explicit separation of severity and verification."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    finding_id: str = Field(min_length=1, strict=True)
    rule_id: str = Field(min_length=1, strict=True)
    title: str = Field(min_length=1, strict=True)
    description: str = Field(min_length=1, strict=True)
    severity: Severity
    status: FindingStatus = FindingStatus.UNVERIFIED
    source_tool: str = Field(min_length=1, strict=True)
    file_path: str = Field(min_length=1, strict=True)
    line_number: int | None = Field(default=None, ge=1, strict=True)
    evidence: str = Field(min_length=1, strict=True)
    cwe: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]*$", strict=True)
    recommendation: str | None = Field(default=None, min_length=1, strict=True)
    confirmation: Confirmation | None = None

    @model_validator(mode="after")
    def check_confirmation(self) -> Self:
        if self.status is FindingStatus.CONFIRMED and self.confirmation is None:
            raise ValueError("confirmed findings require independent confirmation")
        if self.status is not FindingStatus.CONFIRMED and self.confirmation is not None:
            raise ValueError("confirmation is only valid for confirmed findings")
        return self
