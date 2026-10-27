"""Public, source-free summaries of Semgrep scan results."""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from ai_code_security_analyzer.models import Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus


SCHEMA_VERSION = "1.0"
_FIXED_ISSUES = {
    "semgrep_reported_errors", "semgrep_skipped_rules", "semgrep_skipped_paths",
    "no_files_scanned", "semgrep_not_installed", "version_check_failed",
    "required_option_unsupported", "semgrep_timeout", "semgrep_output_limit",
    "semgrep_launch_failed", "invalid_json", "nonzero_exit",
}
_RESULT_ISSUE = re.compile(r"result_[0-9]+_(invalid_result|unknown_severity|multiple_cwe_values|invalid_cwe_metadata)\Z")
_LIMITATIONS = (
    "Findings are unverified static-analysis candidates.",
    "This CLI does not enforce OS-level network isolation.",
    "No findings does not establish that the target is safe.",
)


def _safe_issues(issues: tuple[str, ...]) -> list[str]:
    return [issue if issue in _FIXED_ISSUES or _RESULT_ISSUE.fullmatch(issue) else "redacted_issue" for issue in issues]


def _target_id(target: Path) -> str:
    return hashlib.sha256(os.fsencode(target.resolve())).hexdigest()[:16]


def _severity_counts(scan: ScanResult) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in scan.findings:
        counts[finding.severity.value] += 1
    return counts


def _text_value(value: str) -> str:
    """Escape control characters in untrusted path and rule labels."""
    return json.dumps(value, ensure_ascii=False)[1:-1]


def build_json_report(scan: ScanResult, target: Path, rules: Path) -> dict[str, Any]:
    """Return only validated findings and safe diagnostic codes."""
    return {
        "schema_version": SCHEMA_VERSION,
        "status": scan.status.value,
        "completed": scan.status is ScanStatus.COMPLETED,
        "target": {"id": _target_id(target), "kind": "directory"},
        "tool": {"name": "semgrep", "version": scan.semgrep_version, "exit_code": scan.exit_code},
        "rules": {"file_name": rules.name},
        "summary": {"finding_count": len(scan.findings), "issue_count": len(scan.issues), "by_severity": _severity_counts(scan)},
        "findings": [finding.model_dump(mode="json") for finding in scan.findings],
        "issues": _safe_issues(scan.issues),
        "coverage": {
            "paths_skipped": "semgrep_skipped_paths" in scan.issues,
            "rules_skipped": "semgrep_skipped_rules" in scan.issues,
            "no_files_scanned": "no_files_scanned" in scan.issues,
        },
        "limitations": list(_LIMITATIONS),
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)


def render_text(scan: ScanResult, target: Path, rules: Path) -> str:
    counts = _severity_counts(scan)
    lines = [
        f"Status: {scan.status.value}",
        f"Completed: {'yes' if scan.status is ScanStatus.COMPLETED else 'no'}",
        f"Target ID: {_target_id(target)}",
        f"Tool: semgrep {scan.semgrep_version or 'unknown'}",
        f"Rules: {_text_value(rules.name)}",
        f"Findings: {len(scan.findings)} unverified candidate(s)",
        "Severity: " + ", ".join(f"{name}={count}" for name, count in counts.items()),
    ]
    for finding in scan.findings:
        location = f"{_text_value(finding.file_path)}:{finding.line_number or '?'}"
        lines.append(f"- {location} [{finding.severity.value}] {_text_value(finding.rule_id)} ({finding.status.value})")
    issues = _safe_issues(scan.issues)
    lines.append("Issues: " + (", ".join(issues) if issues else "none"))
    if "semgrep_skipped_paths" in scan.issues:
        lines.append("Coverage: some paths were skipped; path details are withheld.")
    if "semgrep_skipped_rules" in scan.issues:
        lines.append("Coverage: some rules were skipped.")
    if "no_files_scanned" in scan.issues:
        lines.append("Coverage: no files were scanned.")
    lines.extend(f"Limitation: {item}" for item in _LIMITATIONS)
    return "\n".join(lines)


def validate_output_path(output: Path, target: Path, rules_directory: Path) -> None:
    """Reject existing files, symlinked parents, and writes into input trees."""
    absolute = Path(os.path.abspath(output))
    parent = absolute.parent
    if not parent.is_dir() or parent.resolve() != parent:
        raise ValueError("output parent must be a local directory without symlinks")
    if absolute.is_symlink() or absolute.exists():
        raise ValueError("output file already exists")
    if parent.is_relative_to(target.resolve()) or parent.is_relative_to(rules_directory.resolve()):
        raise ValueError("output must be outside the target and rules directories")


def write_new_report(output: Path, contents: str, target: Path, rules_directory: Path) -> None:
    """Create a private report once; never follow a final symlink or overwrite."""
    validate_output_path(output, target, rules_directory)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(contents + "\n")
