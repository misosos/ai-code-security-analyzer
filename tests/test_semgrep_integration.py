"""Optional local scan; never downloads rules or executes the sample source."""

import shutil
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.scan_evidence_manifest import EvidenceStatus
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


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
def test_pinned_semgrep_scan_captures_reported_scope_without_verbose(tmp_path: Path) -> None:
    """Exercise scope extraction from the same real Semgrep JSON as Findings."""
    import subprocess

    version = subprocess.run(
        ["semgrep", "--version"], check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()
    if version != "1.182.1":
        pytest.skip(f"requires Semgrep 1.182.1, found {version}")

    repository = Path(__file__).resolve().parents[1]
    trusted = repository / "rules"
    rules = trusted / "security-baseline.yml"
    target = tmp_path / "synthetic-project"
    target.mkdir()
    (target / "eval.js").write_text('const input = "2 + 2";\neval(input);\n')
    (target / "ignored.js").write_text('eval("ignored synthetic input");\n')
    (target / ".semgrepignore").write_text("ignored.js\n")

    output = SemgrepAdapter(trusted)._scan_with_evidence(target, rules)

    assert output.result.status is ScanStatus.COMPLETED
    assert any(item.rule_id == "baseline.javascript-dynamic-eval" for item in output.result.findings)
    assert output.scope_evidence.scanned_status is EvidenceStatus.OBSERVED
    assert "eval.js" in output.scope_evidence.scanned_paths
    assert "ignored.js" not in output.scope_evidence.scanned_paths
    # Current non-verbose product invocation does not prove why an unreported
    # path was absent. Never turn this into a claim that nothing was skipped.
    assert output.scope_evidence.skipped_status is EvidenceStatus.NOT_COLLECTED
    assert "scanned_paths_do_not_prove_complete_analysis" in output.scope_evidence.limitations


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is not installed")
def test_internal_service_manifest_binds_real_semgrep_findings_and_scope(tmp_path: Path) -> None:
    import subprocess

    version = subprocess.run(
        ["semgrep", "--version"], check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()
    if version != "1.182.1":
        pytest.skip(f"requires Semgrep 1.182.1, found {version}")

    repository = Path(__file__).resolve().parents[1]
    trusted = repository / "rules"
    target = tmp_path / "synthetic-project"
    target.mkdir()
    (target / "eval.js").write_text('const input = "2 + 2";\neval(input);\n')
    (target / ".semgrepignore").write_text("ignored.js\n")
    (target / "ignored.js").write_text('eval("synthetic ignored input");\n')
    service = ScanService(ApiSettings(target, trusted, "z" * 48))

    response, manifest = service._scan_with_manifest("local-project", "baseline")

    assert response.scan_status is ScanStatus.COMPLETED
    assert response.semgrep_version == "1.182.1"
    assert any(item.rule_id == "baseline.javascript-dynamic-eval" for item in response.findings)
    assert manifest.scan_ref
    assert manifest.target_id == "local-project"
    assert manifest.rule_profile_id == "baseline"
    assert manifest.finding_ids == tuple(item.finding_id for item in response.findings)
    assert manifest.finding_count == response.finding_count
    assert manifest.displayed_finding_count == response.displayed_finding_count
    assert manifest.omitted_finding_count == response.omitted_finding_count
    assert manifest.execution_evidence.semgrep_version == response.semgrep_version
    assert manifest.scope_evidence.scanned_status is EvidenceStatus.OBSERVED
    assert "eval.js" in manifest.scope_evidence.scanned_paths
    assert manifest.scope_evidence.skipped_status is EvidenceStatus.NOT_COLLECTED
    assert manifest.scope_evidence.completeness_status is EvidenceStatus.UNVERIFIED
    assert str(tmp_path) not in repr(manifest)
    assert "scan_ref" not in response.model_dump()


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
