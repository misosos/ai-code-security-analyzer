"""Allowlisted, single-flight scan orchestration for the local HTTP API."""

from __future__ import annotations

import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from ai_code_security_analyzer.api.schemas import (
    ApiFinding,
    IssueCode,
    LimitationCode,
    RestrictedClaim,
    RuleProfileOption,
    ScanResponse,
    TargetOption,
)
from ai_code_security_analyzer.evidence_consumer import EvidenceConsumerError, consume_evidence_summary
from ai_code_security_analyzer.evidence_summary import (
    FindingKind,
    build_evidence_summary,
)
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.taint_evidence import TaintEvidence, _TRUSTED_RULES


class ServiceError(Exception):
    def __init__(self, status_code: int, code: str) -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProjectTarget:
    target_id: str
    label: str
    directory: Path = field(repr=False)


@dataclass(frozen=True)
class RegisteredProject:
    target_id: str
    label: str
    directory: Path = field(repr=False)
    device: int
    inode: int


@dataclass(frozen=True)
class ApiSettings:
    target_directory: Path | None
    trusted_rules_directory: Path
    api_token: str
    allowed_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    max_response_bytes: int = 1_048_576
    project_targets: tuple[ProjectTarget, ...] = ()
    registered_targets: tuple[RegisteredProject, ...] = field(init=False, repr=False, default=())

    def __post_init__(self) -> None:
        if not isinstance(self.api_token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,256}", self.api_token):
            raise ValueError("api_token_configuration_invalid")
        if self.max_response_bytes < 1024 or self.max_response_bytes > 4_194_304:
            raise ValueError("response_limit_configuration_invalid")
        rules = _strict_directory(self.trusted_rules_directory)
        if self.target_directory is not None and self.project_targets:
            raise ValueError("target_configuration_ambiguous")
        configured_targets = self.project_targets
        if self.target_directory is not None:
            legacy_directory = Path(self.target_directory)
            if not legacy_directory.is_absolute():
                legacy_directory = Path.cwd() / legacy_directory
            configured_targets = (ProjectTarget(TARGET_ID, "Local Project", legacy_directory),)
        if not configured_targets or len(configured_targets) > _MAX_REGISTERED_TARGETS:
            raise ValueError("target_configuration_invalid")
        registered: list[RegisteredProject] = []
        seen_ids: set[str] = set()
        seen_labels: set[str] = set()
        for item in configured_targets:
            if not isinstance(item.target_id, str) or not _TARGET_ID.fullmatch(item.target_id):
                raise ValueError("target_configuration_invalid")
            if not isinstance(item.label, str) or not _valid_target_label(item.label):
                raise ValueError("target_configuration_invalid")
            label_key = unicodedata.normalize("NFKC", item.label).casefold()
            if item.target_id in seen_ids or label_key in seen_labels:
                raise ValueError("target_configuration_ambiguous")
            seen_ids.add(item.target_id)
            seen_labels.add(label_key)
            directory = _strict_directory(item.directory)
            if _directories_overlap(directory, rules):
                raise ValueError("target_rules_overlap")
            if any(_directories_overlap(directory, prior.directory) for prior in registered):
                raise ValueError("target_configuration_ambiguous")
            stat = directory.stat()
            registered.append(RegisteredProject(item.target_id, item.label, directory, stat.st_dev, stat.st_ino))
        object.__setattr__(self, "registered_targets", tuple(registered))
        # Keep the old attribute available for callers and tests using the legacy
        # single-target configuration. Multi-target callers use registered_targets.
        object.__setattr__(self, "target_directory", registered[0].directory if self.target_directory is not None else None)
        object.__setattr__(self, "trusted_rules_directory", rules)
        if any(not _valid_origin(origin) for origin in self.allowed_origins):
            raise ValueError("origin_configuration_invalid")
        if any(not re.fullmatch(r"[a-zA-Z0-9.-]+", host) for host in self.allowed_hosts):
            raise ValueError("host_configuration_invalid")


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise ValueError("symlink_path_not_allowed")


def _strict_directory(value: Path) -> Path:
    supplied = Path(value)
    if not supplied.is_absolute():
        raise ValueError("directory_configuration_invalid")
    absolute = supplied.anchor and Path(supplied.anchor) or Path("/")
    for component in supplied.parts[1:]:
        if component in {"", "."}:
            continue
        absolute = absolute.parent if component == ".." else absolute / component
        if absolute.is_symlink():
            raise ValueError("symlink_path_not_allowed")
    try:
        resolved = absolute.resolve(strict=True)
    except OSError:
        raise ValueError("directory_configuration_invalid") from None
    _reject_symlink_components(resolved)
    if not resolved.is_dir():
        raise ValueError("directory_configuration_invalid")
    return resolved


def _directories_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _valid_target_label(value: str) -> bool:
    return (
        value == value.strip() and 1 <= len(value) <= 128
        and not any(unicodedata.category(char).startswith("C") for char in value)
    )


def _valid_origin(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 256:
        return False
    try:
        parts = urlsplit(value)
        return (
            parts.scheme == "http" and parts.hostname in {"127.0.0.1", "localhost"}
            and parts.path == "" and parts.query == "" and parts.fragment == ""
            and parts.username is None and parts.password is None
            and (parts.port is None or 1 <= parts.port <= 65535)
        )
    except ValueError:
        return False


@dataclass(frozen=True)
class RuleProfile:
    profile_id: str
    label: str
    relative_path: str
    experimental: bool


RULE_PROFILES = (
    RuleProfile("baseline", "Baseline Rules", "security-baseline.yml", False),
    RuleProfile("eval-experimental", "Experimental JavaScript Eval", "experimental/javascript-eval-taint.yml", True),
    RuleProfile(
        "command-injection-experimental",
        "Experimental Command Injection",
        "experimental/javascript-command-injection-taint.yml",
        True,
    ),
)
TARGET_ID = "local-project"
_TARGET_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")
_MAX_REGISTERED_TARGETS = 32
_SAFE_PATH = re.compile(r"\A[^\x00-\x1f\x7f]{1,512}\Z")
_TAINT_RULE_IDS = frozenset(_TRUSTED_RULES)
_MAX_FINDINGS = 50
_MAX_TARGET_ENTRIES = 100_000
_TARGET_PREFLIGHT_TIMEOUT_SECONDS = 5


class ScanService:
    def __init__(
        self,
        settings: ApiSettings,
        adapter_factory: Callable[[Path], object] = SemgrepAdapter,
    ) -> None:
        self.settings = settings
        self.adapter_factory = adapter_factory
        self._scan_lock = threading.Lock()

    @property
    def target_options(self) -> tuple[TargetOption, ...]:
        return tuple(TargetOption(id=item.target_id, label=item.label) for item in self.settings.registered_targets)

    @property
    def profile_options(self) -> tuple[RuleProfileOption, ...]:
        return tuple(
            RuleProfileOption(id=item.profile_id, label=item.label, experimental=item.experimental)
            for item in RULE_PROFILES
        )

    def scan(self, target_id: str, rule_profile_id: str) -> ScanResponse:
        registered = next((item for item in self.settings.registered_targets if item.target_id == target_id), None)
        if registered is None:
            raise ServiceError(404, "target_not_allowed")
        profile = next((item for item in RULE_PROFILES if item.profile_id == rule_profile_id), None)
        if profile is None:
            raise ServiceError(404, "rule_profile_not_allowed")
        if not self._scan_lock.acquire(blocking=False):
            raise ServiceError(409, "scan_already_running")
        try:
            try:
                # Recheck the allowlist paths immediately before handing them to
                # the adapter; this narrows but cannot eliminate filesystem races.
                target = self._revalidate_target(registered)
                rules_file = self._rules_file(profile)
                adapter = self.adapter_factory(self.settings.trusted_rules_directory)
                output = adapter._scan_with_evidence(target, rules_file)
            except (OSError, ValueError):
                raise ServiceError(400, "target_not_allowed") from None
            except Exception:
                raise ServiceError(500, "internal_error") from None
            response = self._response(output.result, output.taint_evidence, rules_file)
            if len(response.model_dump_json().encode("utf-8")) > self.settings.max_response_bytes:
                raise ServiceError(413, "response_limit_exceeded")
            return response
        except ServiceError:
            raise
        except Exception:
            raise ServiceError(500, "internal_error") from None
        finally:
            self._scan_lock.release()

    def _revalidate_target(self, registered: RegisteredProject) -> Path:
        configured = registered.directory
        _reject_symlink_components(configured)
        target = configured.resolve(strict=True)
        if target != configured or not target.is_dir():
            raise ValueError("target_changed")
        if _directories_overlap(target, self.settings.trusted_rules_directory):
            raise ValueError("target_rules_overlap")
        if any(
            item.target_id != registered.target_id and _directories_overlap(target, item.directory)
            for item in self.settings.registered_targets
        ):
            raise ValueError("target_configuration_ambiguous")
        stat = target.stat()
        if stat.st_dev != registered.device or stat.st_ino != registered.inode:
            raise ValueError("target_changed")
        # Refuse symlinks anywhere below the selected root; this is a conservative
        # check, not an OS-level sandbox and cannot eliminate concurrent races.
        deadline = time.monotonic() + _TARGET_PREFLIGHT_TIMEOUT_SECONDS
        entries_seen = 0
        for root, directories, files in os.walk(target, followlinks=False):
            root_path = Path(root)
            entries_seen += len(directories) + len(files)
            if entries_seen > _MAX_TARGET_ENTRIES or time.monotonic() > deadline:
                raise ValueError("target_preflight_limit")
            if any((root_path / item).is_symlink() for item in (*directories, *files)):
                raise ValueError("target_symlink_not_allowed")
        return target

    def _rules_file(self, profile: RuleProfile) -> Path:
        root = self.settings.trusted_rules_directory
        path = root / profile.relative_path
        _reject_symlink_components(path)
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or not resolved.is_relative_to(root):
            raise ValueError("rule_file_not_allowed")
        return resolved

    def _response(self, scan_result, evidence_items: tuple[TaintEvidence, ...], rules_file: Path) -> ScanResponse:
        findings = scan_result.findings if isinstance(scan_result.findings, tuple) else ()
        evidence_by_id: dict[str, list[TaintEvidence]] = {}
        for evidence in evidence_items:
            if evidence.finding_id:
                evidence_by_id.setdefault(evidence.finding_id, []).append(evidence)
        severity_counts = {severity: 0 for severity in Severity}
        for finding in findings:
            severity_counts[finding.severity] += 1

        api_findings: list[ApiFinding] = []
        scan_is_usable = scan_result.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}
        for finding in findings[:_MAX_FINDINGS]:
            api_findings.append(self._finding(finding, evidence_by_id, scan_result, rules_file, scan_is_usable))

        omitted = max(0, len(findings) - len(api_findings))
        issues = _safe_issues(scan_result.status, scan_result.issues)
        if omitted:
            issues = (*issues, IssueCode.FINDINGS_OMITTED)

        limitations: list[LimitationCode] = [
            LimitationCode.FINDING_COUNT_NOT_CONFIRMED,
            LimitationCode.SCAN_RESULT_IS_NOT_SAFETY_PROOF,
        ]
        if scan_result.status is ScanStatus.PARTIAL:
            limitations.append(LimitationCode.SCAN_PARTIAL)
        if scan_result.status not in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}:
            limitations.append(LimitationCode.SCAN_FAILED)
        if omitted:
            limitations.append(LimitationCode.OMITTED_NOT_VALIDATED)
        return ScanResponse(
            scan_status=scan_result.status,
            completed=scan_result.status is ScanStatus.COMPLETED,
            semgrep_version=scan_result.semgrep_version if isinstance(scan_result.semgrep_version, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", scan_result.semgrep_version) else None,
            finding_count=len(findings),
            displayed_finding_count=len(api_findings),
            omitted_finding_count=omitted,
            severity_counts=severity_counts,
            issues=issues,
            findings=tuple(api_findings),
            limitations=tuple(limitations),
        )

    def _finding(self, finding: Finding, evidence_by_id, scan_result, rules_file: Path, scan_is_usable: bool) -> ApiFinding:
        if finding.status is not FindingStatus.UNVERIFIED or finding.confirmation is not None:
            return _unvalidated(finding, FindingKind.UNCLASSIFIED, "evidence_validation_failed")
        matching = evidence_by_id.get(finding.finding_id, [])
        is_taint_rule = finding.rule_id in _TAINT_RULE_IDS
        if not scan_is_usable or len(matching) > 1 or (is_taint_rule and len(matching) != 1):
            return _unvalidated(finding, FindingKind.UNCLASSIFIED, "evidence_unavailable")
        evidence = matching[0] if matching else None
        try:
            summary = build_evidence_summary(
                finding,
                evidence=evidence,
                scan_result=scan_result,
                rules_file=rules_file,
                trusted_rules_directory=self.settings.trusted_rules_directory,
            )
            validated = consume_evidence_summary(
                summary,
                finding,
                evidence=evidence,
                scan_result=scan_result,
                rules_file=rules_file,
                trusted_rules_directory=self.settings.trusted_rules_directory,
            )
        except (EvidenceConsumerError, ValueError, TypeError):
            return _unvalidated(finding, FindingKind.UNCLASSIFIED, "evidence_validation_failed")
        path = finding.file_path if _SAFE_PATH.fullmatch(finding.file_path) and _safe_relative(finding.file_path) else None
        return ApiFinding(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            severity=finding.severity,
            verification_status=FindingStatus.UNVERIFIED.value,
            finding_kind=validated.finding_kind,
            file_path=path,
            line_number=finding.line_number,
            evidence_validation_status=validated.validation_status.value,
            supported_claims=validated.allowed_claim_types,
            restricted_claims=tuple(
                RestrictedClaim(claim_type=item.claim_type, decision=item.decision, reason_codes=item.reason_codes)
                for item in validated.restricted_claims
            ),
        )


def _safe_relative(path: str) -> bool:
    return (
        not path.startswith("/") and "\\" not in path and ":" not in path
        and all(part not in {"", ".", ".."} for part in path.split("/"))
    )


def _unvalidated(finding: Finding, kind: FindingKind, code: str) -> ApiFinding:
    return ApiFinding(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id if re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", finding.rule_id) else "unclassified",
        severity=finding.severity,
        verification_status="unverified",
        finding_kind=kind,
        file_path=finding.file_path if _SAFE_PATH.fullmatch(finding.file_path) and _safe_relative(finding.file_path) else None,
        line_number=finding.line_number,
        evidence_validation_status="rejected",
        supported_claims=(),
        restricted_claims=(),
        validation_error_code=code,
    )


def _safe_issues(status: ScanStatus, issues: tuple[str, ...]) -> tuple[IssueCode, ...]:
    known = {
        "semgrep_not_installed": IssueCode.SEMGREP_NOT_INSTALLED,
        "semgrep_timeout": IssueCode.SEMGREP_TIMEOUT,
        "semgrep_output_limit": IssueCode.SEMGREP_OUTPUT_LIMIT,
        "invalid_json": IssueCode.INVALID_JSON,
    }
    if status is ScanStatus.PARTIAL and issues:
        return (IssueCode.EVIDENCE_UNAVAILABLE,)
    if status in {ScanStatus.EXECUTION_FAILED, ScanStatus.INVALID_JSON, ScanStatus.TIMED_OUT, ScanStatus.OUTPUT_LIMIT_EXCEEDED}:
        matched = [known[item] for item in issues if item in known]
        return tuple(dict.fromkeys((*matched, IssueCode.SEMGREP_FAILED)))
    if status is ScanStatus.NOT_INSTALLED:
        return (IssueCode.SEMGREP_NOT_INSTALLED,)
    return ()
