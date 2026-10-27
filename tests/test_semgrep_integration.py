"""Optional local scan; never downloads rules or executes the sample source."""

import shutil
from pathlib import Path

import pytest

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
