import json
import os
import sys
from pathlib import Path

import pytest

from ai_code_security_analyzer import semgrep_adapter
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


@pytest.fixture
def paths(tmp_path: Path) -> tuple[SemgrepAdapter, Path, Path]:
    target = tmp_path / "project"
    target.mkdir()
    rules_directory = tmp_path / "trusted-rules"
    rules_directory.mkdir()
    rules = rules_directory / "local.yml"
    rules.write_text("rules: []\n")
    return SemgrepAdapter(rules_directory), target, rules


def finding_json() -> bytes:
    return json.dumps({
        "results": [{
            "check_id": "local.synthetic", "path": "sample.py", "start": {"line": 2},
            "extra": {"message": "Synthetic message", "severity": "WARNING"},
        }],
        "errors": [],
    }).encode()


def fake_semgrep(monkeypatch: pytest.MonkeyPatch, scan_output: bytes, *, exit_code: int = 0) -> list[tuple[list[str], Path]]:
    calls: list[tuple[list[str], Path]] = []
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        calls.append((args, cwd))
        assert "SYNTHETIC_SECRET" not in env
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.160.0\n")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(0, b"--json --metrics --disable-version-check --oss-only --no-autofix")
        return semgrep_adapter._ProcessResult(exit_code, scan_output)

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    return calls


def test_scan_uses_local_rules_and_sanitized_environment(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setenv("SYNTHETIC_SECRET", "synthetic-token")
    calls = fake_semgrep(monkeypatch, finding_json())

    scanned = adapter.scan(target, rules)

    assert scanned.status is ScanStatus.COMPLETED
    assert scanned.semgrep_version == "1.160.0"
    assert len(scanned.findings) == 1
    assert scanned.findings[0].status.value == "unverified"
    args, cwd = calls[-1]
    assert args[1:7] == ["scan", "--json", "--metrics=off", "--disable-version-check", "--oss-only", "--no-autofix"]
    assert args[-3:] == [rules.name, "--", str(target)]
    assert cwd == rules.parent
    assert "auto" not in args
    assert "--autofix" not in args


def test_clean_scan_with_zero_findings(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b'{"results": [], "errors": []}')
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.COMPLETED
    assert scanned.findings == ()


def test_reported_errors_make_scan_partial(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    payload = json.loads(finding_json())
    payload["errors"] = [{"message": "sensitive source text"}]
    fake_semgrep(monkeypatch, json.dumps(payload).encode())
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.PARTIAL
    assert len(scanned.findings) == 1
    assert scanned.issues == ("semgrep_reported_errors",)


def test_missing_semgrep_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: None)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.NOT_INSTALLED
    assert scanned.findings == ()


def test_nonzero_exit_is_failure_even_with_findings(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, finding_json(), exit_code=2)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert len(scanned.findings) == 1
    assert scanned.exit_code == 2


def test_invalid_json_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b"{broken")
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.INVALID_JSON
    assert scanned.findings == ()


def test_bad_json_with_nonzero_exit_is_execution_failure(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    fake_semgrep(monkeypatch, b"{broken", exit_code=2)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert scanned.issues == ("invalid_json",)


def test_unsupported_required_option_stops_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.160.0")
        return semgrep_adapter._ProcessResult(0, b"--json")

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.EXECUTION_FAILED
    assert scanned.issues == ("required_option_unsupported",)


def test_timeout_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def timeout(*args: object, **kwargs: object) -> None:
        raise semgrep_adapter._ProcessTimeout

    monkeypatch.setattr(semgrep_adapter, "_run_process", timeout)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.TIMED_OUT
    assert scanned.findings == ()


def test_output_limit_is_not_clean_scan(paths: tuple[SemgrepAdapter, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, target, rules = paths
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def too_large(*args: object, **kwargs: object) -> None:
        raise semgrep_adapter._OutputLimitExceeded

    monkeypatch.setattr(semgrep_adapter, "_run_process", too_large)
    scanned = adapter.scan(target, rules)
    assert scanned.status is ScanStatus.OUTPUT_LIMIT_EXCEEDED


def test_untrusted_or_missing_paths_are_rejected(paths: tuple[SemgrepAdapter, Path, Path], tmp_path: Path) -> None:
    adapter, target, rules = paths
    with pytest.raises(ValueError, match="target"):
        adapter.scan(tmp_path / "missing", rules)
    untrusted = target / "local.yml"
    untrusted.write_text("rules: []\n")
    with pytest.raises(ValueError, match="trusted rules"):
        adapter.scan(target, untrusted)
    nested_target = rules.parent / "untrusted-project"
    nested_target.mkdir()
    with pytest.raises(ValueError, match="separate trusted rules"):
        adapter.scan(nested_target, rules)


def test_runner_enforces_output_limit(tmp_path: Path) -> None:
    with pytest.raises(semgrep_adapter._OutputLimitExceeded):
        semgrep_adapter._run_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2000001)"],
            tmp_path, {"PATH": os.defpath}, 5,
        )


def test_runner_enforces_timeout(tmp_path: Path) -> None:
    with pytest.raises(semgrep_adapter._ProcessTimeout):
        semgrep_adapter._run_process(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            tmp_path, {"PATH": os.defpath}, 1,
        )
