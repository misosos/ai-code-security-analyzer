"""Optional local scan; never downloads rules or executes the sample source."""

import shutil
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_local_rule_scans_synthetic_source(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.py").write_text('eval("1 + 1")\n')
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    rules = trusted / "sample.yml"
    rules.write_text(
        "rules:\n"
        "  - id: local.synthetic-eval\n"
        "    languages: [python]\n"
        "    severity: WARNING\n"
        "    message: Synthetic eval pattern\n"
        "    pattern: eval(...)\n"
    )

    scanned = SemgrepAdapter(trusted).scan(target, rules)

    assert scanned.status is ScanStatus.COMPLETED
    assert len(scanned.findings) == 1
    assert scanned.findings[0].status.value == "unverified"
    assert scanned.findings[0].file_path == "sample.py"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_typescript_vulnerable_and_safe_pair(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    synthetic_marker = "SYNTHETIC_TEST_TOKEN_123"
    (target / "vulnerable.ts").write_text(f'const result = eval("{synthetic_marker}");\n')
    (target / "safe.ts").write_text('const result = JSON.parse("{\\"ok\\":true}");\n')
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    rules = trusted / "typescript.yml"
    rules.write_text(
        "rules:\n"
        "  - id: local.synthetic-eval-ts\n"
        "    languages: [typescript]\n"
        "    severity: ERROR\n"
        "    message: Synthetic dynamic evaluation match\n"
        "    metadata:\n"
        "      cwe: [\"CWE-95: Dynamic Code Evaluation\"]\n"
        "    pattern: eval(...)\n"
    )

    adapter = SemgrepAdapter(trusted)
    vulnerable = adapter.scan(target / "vulnerable.ts", rules)
    repeated = adapter.scan(target / "vulnerable.ts", rules)
    safe = adapter.scan(target / "safe.ts", rules)

    assert vulnerable.status is ScanStatus.COMPLETED
    assert repeated.status is ScanStatus.COMPLETED
    assert safe.status is ScanStatus.COMPLETED
    assert len(vulnerable.findings) == len(repeated.findings) == 1
    assert safe.findings == ()
    finding = vulnerable.findings[0]
    assert finding.source_tool == "semgrep"
    assert finding.rule_id.endswith("local.synthetic-eval-ts")
    assert finding.file_path == "vulnerable.ts"
    assert finding.line_number == 1
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-95"
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.finding_id == repeated.findings[0].finding_id
    assert finding.finding_id.startswith("semgrep:")
    assert str(tmp_path) not in finding.finding_id
    assert synthetic_marker not in finding.model_dump_json()
    assert synthetic_marker not in repr(vulnerable)
