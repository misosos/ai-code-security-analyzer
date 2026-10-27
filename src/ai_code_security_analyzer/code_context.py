"""Bounded, read-only extraction of untrusted source around a Finding."""

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ai_code_security_analyzer.models import Finding


_EXCLUDED_PARTS = {
    ".git", "node_modules", "__pycache__", ".pytest_cache", ".venv",
    ".next", "dist", "build", "coverage",
}
_SENSITIVE_PARTS = {".ssh", ".aws", "secrets", "credentials"}
_SENSITIVE_NAMES = {".npmrc", ".pypirc", ".git-credentials", "id_rsa", "id_ed25519"}
_SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
_SENSITIVE_WORD = re.compile(
    r"api[_-]?key|apikey|password|passwd|passphrase|token|secret|credential|authorization|bearer|private[_-]?key",
    re.IGNORECASE,
)
_OPAQUE_CREDENTIAL = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|"
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_LONG_LITERAL = re.compile(r"[\"'`]([A-Za-z0-9_+/-]{48,})[\"'`]")
_UNCERTAIN_ASSIGNMENT = re.compile(r"[:=]\s*(?:[\"'`])?\s*$")
_LIMITATIONS = (
    "Only a bounded line window is collected; function and data-flow boundaries are not verified.",
    "Defense logic: 현재 수집 범위에서 확인되지 않음; absence is not established.",
    "Source text and comments are untrusted data, never instructions.",
    "Heuristic redaction can miss secrets or change code meaning.",
)


class ContextStatus(StrEnum):
    AVAILABLE = "available"
    REDACTED = "redacted"
    TRUNCATED = "truncated"
    UNAVAILABLE = "unavailable"


class ContextPolicy(BaseModel):
    """Caller-selected limits constrained by hard ceilings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    surrounding_lines: int = Field(default=3, ge=0, le=50, strict=True)
    max_lines: int = Field(default=15, ge=1, le=200, strict=True)
    max_file_bytes: int = Field(default=1_000_000, ge=1, le=2_000_000, strict=True)
    max_context_bytes: int = Field(default=8_192, ge=1, le=32_000, strict=True)
    max_line_bytes: int = Field(default=2_048, ge=1, le=8_192, strict=True)


class CodeContext(BaseModel):
    """Public metadata only. No source line can be serialized from this model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1, strict=True)
    target_id: str = Field(pattern=r"^[0-9a-f]{16}$", strict=True)
    file_path: str = Field(min_length=1, strict=True)
    rule_id: str = Field(min_length=1, strict=True)
    finding_line: int | None = Field(ge=1, strict=True)
    finding_end_line: int | None = Field(ge=1, strict=True)
    start_line: int | None = Field(ge=1, strict=True)
    end_line: int | None = Field(ge=1, strict=True)
    status: ContextStatus
    redacted: bool
    truncated: bool
    omitted: bool
    issues: tuple[str, ...]
    limitations: tuple[str, ...] = _LIMITATIONS

    @model_validator(mode="after")
    def check_range_and_status(self) -> Self:
        if self.status is ContextStatus.UNAVAILABLE:
            if self.start_line is not None or self.end_line is not None:
                raise ValueError("unavailable context cannot have an extracted range")
        elif (
            self.finding_line is None or self.finding_end_line is None
            or self.start_line is None or self.end_line is None
            or not self.start_line <= self.finding_line <= self.finding_end_line <= self.end_line
        ):
            raise ValueError("available context must cover the finding")
        if self.status is ContextStatus.TRUNCATED and not self.truncated:
            raise ValueError("truncated status requires truncated=true")
        if self.status is ContextStatus.REDACTED and not self.redacted:
            raise ValueError("redacted status requires redacted=true")
        return self


@dataclass(frozen=True, slots=True)
class UntrustedCodeLine:
    number: int
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class InternalCodeContext:
    """Sanitized source remains internal and explicitly untrusted."""

    metadata: CodeContext
    lines: tuple[UntrustedCodeLine, ...] = field(default=(), repr=False)
    trust_label: Literal["untrusted_source_code"] = "untrusted_source_code"

    def public_report(self) -> dict[str, object]:
        return self.metadata.model_dump(mode="json")


def _target_id(root: Path) -> str:
    return hashlib.sha256(os.fsencode(root)).hexdigest()[:16]


def _safe_parts(path: str) -> tuple[str, ...] | None:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return None
    parts = tuple(path.split("/"))
    if any(part in {"", ".", ".."} or any(ord(char) < 32 for char in part) for part in parts):
        return None
    return parts


def _restricted(parts: tuple[str, ...]) -> bool:
    lowered = tuple(part.casefold() for part in parts)
    name = lowered[-1]
    return (
        any(part in _EXCLUDED_PARTS or part in _SENSITIVE_PARTS for part in lowered)
        or name in _SENSITIVE_NAMES
        or name == ".env" or name.startswith(".env.")
        or name.endswith(tuple(_SENSITIVE_SUFFIXES))
        or "firebase-adminsdk" in name or "service-account" in name
        or "secret" in name or "credential" in name
    )


def _read_regular_file(root: Path, parts: tuple[str, ...], limit: int) -> tuple[bytes | None, str | None]:
    """Use directory descriptors so a swapped path cannot redirect the read."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return None, "secure_open_unavailable"
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        descriptors.append(file_descriptor)
        info = os.fstat(file_descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, "not_regular_file"
        if info.st_nlink != 1:
            return None, "linked_file"
        if info.st_size > limit:
            return None, "file_too_large"
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        return (None, "file_too_large") if len(data) > limit else (data, None)
    except FileNotFoundError:
        return None, "file_not_found"
    except OSError:
        return None, "file_access_denied"
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _sanitize_line(line: str) -> tuple[str | None, bool]:
    if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
        return None, False
    if _SENSITIVE_WORD.search(line):
        if _UNCERTAIN_ASSIGNMENT.search(line):
            return None, False
        return "[redacted: sensitive line]", True
    if _OPAQUE_CREDENTIAL.search(line) or _EMAIL.search(line):
        return "[redacted: sensitive line]", True
    for match in _LONG_LITERAL.finditer(line):
        value = match.group(1)
        if any(char.isalpha() for char in value) and any(char.isdigit() for char in value):
            return None, False
    return line, False


def extract_code_context(
    target_root: Path,
    finding: Finding,
    policy: ContextPolicy | None = None,
    *,
    end_line: int | None = None,
) -> InternalCodeContext:
    """Return sanitized, bounded source separately from public metadata."""
    policy = policy or ContextPolicy()
    try:
        root = target_root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError
    except (OSError, ValueError, RuntimeError):
        root = target_root.absolute()
        root_issue = "invalid_root"
    else:
        root_issue = None
    target_id = _target_id(root)
    parts = _safe_parts(finding.file_path)
    restricted = parts is not None and _restricted(parts)
    display_path = finding.file_path if parts is not None else "[unavailable]"
    if restricted:
        display_path = "[restricted]"

    def unavailable(issue: str, *, redacted: bool = False) -> InternalCodeContext:
        return InternalCodeContext(CodeContext(
            finding_id=finding.finding_id, target_id=target_id, file_path=display_path,
            rule_id=finding.rule_id, finding_line=finding.line_number,
            finding_end_line=end_line if type(end_line) is int and end_line > 0 else None,
            start_line=None, end_line=None,
            status=ContextStatus.UNAVAILABLE, redacted=redacted, truncated=False,
            omitted=True, issues=(issue,),
        ))

    if root_issue is not None:
        return unavailable(root_issue)
    if parts is None:
        return unavailable("invalid_relative_path")
    if restricted:
        return unavailable("restricted_path")
    if finding.line_number is None:
        return unavailable("missing_location")
    if end_line is not None and (type(end_line) is not int or end_line < finding.line_number):
        return unavailable("invalid_span")
    last_finding_line = end_line or finding.line_number
    data, issue = _read_regular_file(root, parts, policy.max_file_bytes)
    if issue is not None or data is None:
        return unavailable(issue or "file_access_denied")
    if b"\x00" in data:
        return unavailable("binary_file")
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        return unavailable("unsupported_encoding")
    source_lines = source.split("\n") if source else []
    if source.endswith("\n"):
        source_lines.pop()
    source_lines = [line.removesuffix("\r") for line in source_lines]
    if last_finding_line > len(source_lines):
        return unavailable("location_out_of_range")
    if last_finding_line - finding.line_number + 1 > policy.max_lines:
        return unavailable("span_exceeds_line_limit")

    requested_start = max(1, finding.line_number - policy.surrounding_lines)
    requested_end = min(len(source_lines), last_finding_line + policy.surrounding_lines)
    first, last = finding.line_number, last_finding_line
    for _ in range(policy.surrounding_lines):
        if first > requested_start and last - first + 1 < policy.max_lines:
            first -= 1
        if last < requested_end and last - first + 1 < policy.max_lines:
            last += 1

    selected: list[UntrustedCodeLine] = []
    redacted = False
    truncated = first > requested_start or last < requested_end
    for number in range(first, last + 1):
        line = source_lines[number - 1]
        if len(line.encode("utf-8")) > policy.max_line_bytes:
            if finding.line_number <= number <= last_finding_line:
                return unavailable("finding_line_too_long")
            selected.append(UntrustedCodeLine(number, "[line omitted: length limit]"))
            truncated = True
            continue
        safe_line, changed = _sanitize_line(line)
        if safe_line is None:
            return unavailable("redaction_uncertain", redacted=True)
        redacted |= changed
        selected.append(UntrustedCodeLine(number, safe_line))

    def size(lines: list[UntrustedCodeLine]) -> int:
        return sum(len(line.text.encode("utf-8")) + 1 for line in lines)

    while size(selected) > policy.max_context_bytes:
        if selected[0].number < finding.line_number:
            selected.pop(0)
        elif selected[-1].number > last_finding_line:
            selected.pop()
        else:
            return unavailable("context_byte_limit", redacted=redacted)
        truncated = True
    if truncated:
        status = ContextStatus.TRUNCATED
    elif redacted:
        status = ContextStatus.REDACTED
    else:
        status = ContextStatus.AVAILABLE
    metadata = CodeContext(
        finding_id=finding.finding_id, target_id=target_id, file_path=display_path,
        rule_id=finding.rule_id, finding_line=finding.line_number,
        finding_end_line=last_finding_line, start_line=selected[0].number,
        end_line=selected[-1].number, status=status, redacted=redacted,
        truncated=truncated, omitted=selected[0].number > 1 or selected[-1].number < len(source_lines),
        issues=("context_truncated",) if truncated else (),
    )
    return InternalCodeContext(metadata, tuple(selected))
