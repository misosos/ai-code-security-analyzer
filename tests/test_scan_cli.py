import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ai_code_security_analyzer import cli
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus


@pytest.fixture
def inputs(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    rules = trusted / "sample.yml"
    rules.write_text("rules: []\n")
    return target, rules


def finding(severity: Severity = Severity.HIGH, *, number: int = 1) -> Finding:
    return Finding(
        finding_id=f"semgrep:synthetic{number}",
        rule_id="local.synthetic",
        title="local.synthetic",
        description="Static analysis rule matched.",
        severity=severity,
        source_tool="semgrep",
        file_path=f"src/sample{number}.ts",
        line_number=number,
        evidence=f"Rule matched at line {number}.",
    )


def mock_scan(monkeypatch: pytest.MonkeyPatch, result: ScanResult) -> None:
    monkeypatch.setattr(cli.SemgrepAdapter, "scan", lambda self, target, rules: result)


def argv(target: Path, rules: Path, *extra: str) -> list[str]:
    return ["scan", "--path", str(target), "--rules", str(rules), *extra]


def test_scan_help_and_missing_arguments() -> None:
    help_result = subprocess.run(
        [sys.executable, "-m", "ai_code_security_analyzer", "scan", "--help"],
        capture_output=True, text=True, check=False,
    )
    missing = subprocess.run(
        [sys.executable, "-m", "ai_code_security_analyzer", "scan", "--path", "example"],
        capture_output=True, text=True, check=False,
    )
    assert help_result.returncode == 0
    assert "--path" in help_result.stdout and "--rules" in help_result.stdout
    assert "review" in help_result.stdout
    assert "review-md" in help_result.stdout
    assert missing.returncode == cli.EXIT_INVALID_INPUT
    assert missing.stdout == ""


def test_invalid_target_and_untrusted_rules(inputs: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    target, rules = inputs
    assert cli.main(argv(target / "missing", rules)) == cli.EXIT_INVALID_INPUT
    untrusted = target / "local.yml"
    untrusted.write_text("rules: []\n")
    assert cli.main(argv(target, untrusted)) == cli.EXIT_INVALID_INPUT
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid local" in captured.err


def test_valid_json_report_and_severity_counts(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED, (finding(), finding(Severity.MEDIUM, number=2)), semgrep_version="1.182.1"))

    assert cli.main(argv(target, rules, "--format", "json")) == cli.EXIT_COMPLETE
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert captured.err == ""
    assert report["schema_version"] == "1.0"
    assert report["status"] == "completed" and report["completed"] is True
    assert report["target"]["kind"] == "directory"
    assert str(target) not in captured.out
    assert report["tool"] == {"name": "semgrep", "version": "1.182.1", "exit_code": None}
    assert report["rules"] == {"file_name": "sample.yml"}
    assert report["summary"]["finding_count"] == 2
    assert report["summary"]["issue_count"] == 0
    assert report["summary"]["by_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert report["findings"][0]["finding_id"] == "semgrep:synthetic1"
    assert report["findings"][0]["status"] == FindingStatus.UNVERIFIED.value


def test_clean_scan_is_not_described_as_safe(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED))
    assert cli.main(argv(target, rules, "--format", "json")) == cli.EXIT_COMPLETE
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["finding_count"] == 0
    assert any("does not establish" in item for item in report["limitations"])


def test_partial_status_and_safe_issue_codes(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target, rules = inputs
    marker = "SYNTHETIC_SECRET_DO_NOT_REPORT"
    mock_scan(monkeypatch, ScanResult(ScanStatus.PARTIAL, (finding(),), ("semgrep_skipped_paths", marker)))
    assert cli.main(argv(target, rules, "--format", "json")) == cli.EXIT_PARTIAL
    raw = capsys.readouterr().out
    report = json.loads(raw)
    assert report["completed"] is False
    assert report["issues"] == ["semgrep_skipped_paths", "redacted_issue"]
    assert report["coverage"]["paths_skipped"] is True
    assert marker not in raw


@pytest.mark.parametrize("status", [ScanStatus.EXECUTION_FAILED, ScanStatus.NOT_INSTALLED, ScanStatus.INVALID_JSON, ScanStatus.TIMED_OUT])
def test_full_failure_exit_code(
    status: ScanStatus, inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(status, issues=("nonzero_exit",)))
    assert cli.main(argv(target, rules, "--format", "json")) == cli.EXIT_FAILED
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == status.value and report["completed"] is False


def test_default_text_report(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.PARTIAL, (finding(),), ("semgrep_skipped_paths",)))
    assert cli.main(argv(target, rules)) == cli.EXIT_PARTIAL
    text = capsys.readouterr().out
    assert "Status: partial" in text
    assert "Completed: no" in text
    assert "Findings: 1 unverified candidate(s)" in text
    assert "src/sample1.ts:1 [high] local.synthetic" in text
    assert "semgrep_skipped_paths" in text
    assert "some paths were skipped" in text


def test_text_escapes_control_characters(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target, rules = inputs
    malicious = finding().model_copy(update={"file_path": "src/evil\nStatus: completed.ts", "rule_id": "rule\nCompleted: yes"})
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED, (malicious,)))
    assert cli.main(argv(target, rules)) == cli.EXIT_COMPLETE
    text = capsys.readouterr().out
    assert "src/evil\\nStatus: completed.ts" in text
    assert "rule\\nCompleted: yes" in text
    assert text.count("\nStatus: completed") == 0


def test_json_output_creates_private_file_without_stdout(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED, (finding(),)))
    output = tmp_path / "report.json"
    assert cli.main(argv(target, rules, "--format", "json", "--output", str(output))) == cli.EXIT_COMPLETE
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text())["summary"]["finding_count"] == 1
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_output_rejects_existing_symlink_and_input_trees(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED))
    existing = tmp_path / "existing.json"
    existing.write_text("unchanged")
    link = tmp_path / "report-link.json"
    link.symlink_to(existing)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    for output in (existing, link, linked_parent / "new.json", target / "inside.json", rules.parent / "inside.json"):
        assert cli.main(argv(target, rules, "--format", "json", "--output", str(output))) == cli.EXIT_INVALID_INPUT
    assert existing.read_text() == "unchanged"
    assert capsys.readouterr().out == ""


def test_output_requires_json(inputs: tuple[Path, Path], capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target, rules = inputs
    assert cli.main(argv(target, rules, "--output", str(tmp_path / "report.json"))) == cli.EXIT_INVALID_INPUT
    assert capsys.readouterr().out == ""


def test_output_race_reports_failure_without_traceback(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED))

    def race(*args: object) -> None:
        raise FileExistsError("synthetic race")

    monkeypatch.setattr(cli, "write_new_report", race)
    assert cli.main(argv(target, rules, "--format", "json", "--output", str(tmp_path / "new.json"))) == cli.EXIT_FAILED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "synthetic race" not in captured.err


def test_markdown_output_is_opt_in_and_uses_single_evidence_scan(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    output = tmp_path / "review.md"
    scan = ScanResult(ScanStatus.COMPLETED, (finding(),), (), 0, "1.182.1")
    calls = []

    def scan_with_evidence(self, passed_target, passed_rules):
        from ai_code_security_analyzer.semgrep_adapter import _ScanOutput
        calls.append((passed_target, passed_rules))
        return _ScanOutput(scan)

    monkeypatch.setattr(cli.SemgrepAdapter, "_scan_with_evidence", scan_with_evidence)
    monkeypatch.setattr(cli.SemgrepAdapter, "scan", lambda *_args: pytest.fail("must not scan twice"))
    status = cli.main(argv(target, rules, "--format", "review-md", "--output", str(output)))
    captured = capsys.readouterr()
    assert status == cli.EXIT_COMPLETE
    assert len(calls) == 1
    assert captured.out == ""
    assert captured.err == ""
    assert output.read_text().startswith("# AI Code Security Analyzer — Analyst Review Report")
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_markdown_stdout_and_existing_formats_keep_output_policy(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    scan = ScanResult(ScanStatus.COMPLETED, (), (), 0, "1.182.1")
    mock_scan(monkeypatch, scan)
    from ai_code_security_analyzer.semgrep_adapter import _ScanOutput
    monkeypatch.setattr(cli.SemgrepAdapter, "_scan_with_evidence", lambda *_args, **_kwargs: _ScanOutput(scan))
    assert cli.main(argv(target, rules, "--format", "review-md")) == cli.EXIT_COMPLETE
    assert capsys.readouterr().out.startswith("# AI Code Security Analyzer — Analyst Review Report")
    for format_name in ("text", "review"):
        assert cli.main(argv(target, rules, "--format", format_name, "--output", str(tmp_path / "bad"))) == cli.EXIT_INVALID_INPUT
    assert "requires --format json or review-md" in capsys.readouterr().err


def test_markdown_output_rejects_existing_and_input_tree_paths(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    mock_scan(monkeypatch, ScanResult(ScanStatus.COMPLETED))
    existing = tmp_path / "existing.md"
    existing.write_text("keep")
    link = tmp_path / "report-link.md"
    link.symlink_to(existing)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    for output in (
        existing,
        link,
        linked_parent / "new.md",
        target / "inside.md",
        rules.parent / "inside.md",
    ):
        result = cli.main(argv(target, rules, "--format", "review-md", "--output", str(output)))
        assert result == cli.EXIT_INVALID_INPUT
    assert existing.read_text() == "keep"
    assert capsys.readouterr().out == ""


def test_markdown_output_failure_is_generic_and_does_not_leak_path(
    inputs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    target, rules = inputs
    scan = ScanResult(ScanStatus.COMPLETED, (), (), 0, "1.182.1")
    from ai_code_security_analyzer.semgrep_adapter import _ScanOutput
    monkeypatch.setattr(cli.SemgrepAdapter, "_scan_with_evidence", lambda *_args, **_kwargs: _ScanOutput(scan))

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"synthetic path failure {tmp_path}")

    monkeypatch.setattr(cli, "write_new_report", fail_write)
    output = tmp_path / "secret-path.md"
    result = cli.main(argv(target, rules, "--format", "review-md", "--output", str(output)))
    captured = capsys.readouterr()
    assert result == cli.EXIT_FAILED
    assert captured.out == ""
    assert "secret-path.md" not in captured.err
    assert "synthetic path failure" not in captured.err
