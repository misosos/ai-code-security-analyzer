"""Local-only Semgrep execution with bounded output and explicit scan states."""

import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ai_code_security_analyzer.models import Finding
from ai_code_security_analyzer.semgrep_parser import InvalidSemgrepJson, _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import TaintEvidence, build_taint_evidence


MAX_OUTPUT_BYTES = 2_000_000
SCAN_TIMEOUT_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 10
_REQUIRED_OPTIONS = ("--json", "--metrics", "--disable-version-check", "--oss-only", "--no-autofix")
_VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+\b")


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    EXECUTION_FAILED = "execution_failed"
    NOT_INSTALLED = "not_installed"
    INVALID_JSON = "invalid_json"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


@dataclass(frozen=True)
class ScanResult:
    status: ScanStatus
    findings: tuple[Finding, ...] = ()
    issues: tuple[str, ...] = ()
    exit_code: int | None = None
    semgrep_version: str | None = None


@dataclass(frozen=True)
class _ScanOutput:
    result: ScanResult
    taint_evidence: tuple[TaintEvidence, ...] = ()


@dataclass(frozen=True)
class _ProcessResult:
    exit_code: int
    stdout: bytes


class _ProcessTimeout(Exception):
    pass


class _OutputLimitExceeded(Exception):
    pass


def _resolve_path(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, ValueError, RuntimeError):
        raise ValueError("invalid local path") from None


def _stop_process(process: subprocess.Popen[bytes], *, force_group: bool = False) -> None:
    running = process.poll() is None
    if os.name == "posix" and (running or force_group):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif running:
        process.kill()
    process.wait()


def _run_process(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> _ProcessResult:
    process = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    assert process.stdout is not None and process.stderr is not None
    output = bytearray()
    total_bytes = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _ProcessTimeout
                for key, _ in selector.select(min(remaining, 0.5)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_OUTPUT_BYTES:
                        raise _OutputLimitExceeded
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProcessTimeout
        return _ProcessResult(process.wait(timeout=remaining), bytes(output))
    except subprocess.TimeoutExpired:
        _stop_process(process, force_group=True)
        raise _ProcessTimeout from None
    except BaseException:
        _stop_process(process, force_group=True)
        raise
    finally:
        process.stdout.close()
        process.stderr.close()


class SemgrepAdapter:
    """Run a scan with rules from a separately trusted local directory."""

    def __init__(self, trusted_rules_directory: Path) -> None:
        root = _resolve_path(trusted_rules_directory)
        if not root.is_dir():
            raise ValueError("trusted rules directory must exist")
        self.trusted_rules_directory = root

    def scan(self, target: Path, rules_file: Path, *, timeout: int = SCAN_TIMEOUT_SECONDS) -> ScanResult:
        """Run a scan and preserve the established public ScanResult contract."""
        return self._scan_with_evidence(target, rules_file, timeout=timeout).result

    def _scan_with_evidence(
        self, target: Path, rules_file: Path, *, timeout: int = SCAN_TIMEOUT_SECONDS
    ) -> _ScanOutput:
        """Internal scan path returning derived taint evidence from the same JSON parse."""
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        project = _resolve_path(target)
        if not project.exists() or not (project.is_dir() or project.is_file()):
            raise ValueError("target must be an existing local file or directory")
        project_root = project if project.is_dir() else project.parent
        rules = _resolve_path(rules_file)
        if not rules.is_file() or rules.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError("rules file must be a local YAML file")
        if (
            not rules.is_relative_to(self.trusted_rules_directory)
            or project_root.is_relative_to(self.trusted_rules_directory)
            or self.trusted_rules_directory.is_relative_to(project_root)
        ):
            raise ValueError("rules file must be inside the separate trusted rules directory")

        executable = shutil.which("semgrep")
        if executable is None:
            return _ScanOutput(ScanResult(ScanStatus.NOT_INSTALLED, issues=("semgrep_not_installed",)))

        with tempfile.TemporaryDirectory(prefix="ai-code-semgrep-") as temporary_home:
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": temporary_home,
                "XDG_CACHE_HOME": temporary_home,
                "SEMGREP_SEND_METRICS": "off",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
            }
            try:
                version_result = _run_process([executable, "--version"], project_root, env, PROBE_TIMEOUT_SECONDS)
                version_match = _VERSION_PATTERN.search(version_result.stdout.decode("utf-8", errors="replace"))
                if version_result.exit_code != 0 or version_match is None:
                    return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("version_check_failed",)))
                version = version_match.group()
                help_result = _run_process([executable, "scan", "--help"], project_root, env, PROBE_TIMEOUT_SECONDS)
                help_text = help_result.stdout.decode("utf-8", errors="replace")
                if help_result.exit_code != 0 or any(option not in help_text for option in _REQUIRED_OPTIONS):
                    return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("required_option_unsupported",), semgrep_version=version))
                args = [
                    executable, "scan", "--json", "--metrics=off", "--disable-version-check",
                    "--oss-only", "--no-autofix", "--config", rules.name, "--", str(project),
                ]
                # A relative config name prevents Semgrep from embedding the local
                # rules directory in check_id values exposed by public reports.
                completed = _run_process(args, rules.parent, env, timeout)
            except _ProcessTimeout:
                return _ScanOutput(ScanResult(ScanStatus.TIMED_OUT, issues=("semgrep_timeout",)))
            except _OutputLimitExceeded:
                return _ScanOutput(ScanResult(ScanStatus.OUTPUT_LIMIT_EXCEEDED, issues=("semgrep_output_limit",)))
            except OSError:
                return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("semgrep_launch_failed",)))

        try:
            semgrep_document = _parse_semgrep_json_internal(completed.stdout, project_root)
        except InvalidSemgrepJson:
            if completed.exit_code != 0:
                return _ScanOutput(ScanResult(ScanStatus.EXECUTION_FAILED, issues=("invalid_json",), exit_code=completed.exit_code, semgrep_version=version))
            return _ScanOutput(ScanResult(ScanStatus.INVALID_JSON, issues=("invalid_json",), exit_code=completed.exit_code, semgrep_version=version))
        parsed = semgrep_document.parsed
        taint_evidence = build_taint_evidence(
            semgrep_document.document,
            semgrep_document.result_findings,
            project_root,
            rules_file=rules,
            trusted_rules_directory=self.trusted_rules_directory,
        )
        if completed.exit_code != 0:
            return _ScanOutput(
                ScanResult(ScanStatus.EXECUTION_FAILED, parsed.findings, parsed.issues + ("nonzero_exit",), completed.exit_code, version),
                taint_evidence,
            )
        status = ScanStatus.PARTIAL if parsed.issues else ScanStatus.COMPLETED
        return _ScanOutput(ScanResult(status, parsed.findings, parsed.issues, completed.exit_code, version), taint_evidence)
