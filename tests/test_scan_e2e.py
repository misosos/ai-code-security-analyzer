"""Full CLI-to-Finding check with a local rule and synthetic TypeScript files."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_scan_cli_with_real_semgrep(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    marker = "SYNTHETIC_E2E_TOKEN_456"
    (target / "vulnerable.ts").write_text(
        f"export function unsafe(input: string) {{\n  return eval(input /* {marker} */);\n}}\n"
    )
    (target / "safe.ts").write_text(
        "export function safe(input: string) { return JSON.parse(input); }\n"
    )
    rules = Path(__file__).resolve().parents[1] / "rules" / "example-typescript-eval.yml"

    completed = subprocess.run(
        [
            sys.executable, "-m", "ai_code_security_analyzer", "scan",
            "--path", str(target), "--rules", str(rules), "--format", "json",
        ],
        capture_output=True, text=True, check=False, timeout=90,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["status"] == "completed" and report["completed"] is True
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["by_severity"]["high"] == 1
    finding = report["findings"][0]
    assert finding["file_path"] == "vulnerable.ts"
    assert finding["line_number"] == 2
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-95"
    assert finding["status"] == "unverified"
    assert finding["finding_id"].startswith("semgrep:")
    assert str(tmp_path) not in completed.stdout
    assert marker not in completed.stdout
