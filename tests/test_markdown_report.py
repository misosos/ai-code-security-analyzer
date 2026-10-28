"""Markdown analyst report tests use synthetic findings only."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ai_code_security_analyzer import markdown_report, review
from ai_code_security_analyzer.evidence_consumer import EvidenceConsumerError
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import build_taint_evidence


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
CANARY = "SYNTHETIC_MARKDOWN_REPORT_CANARY"


def _taint_case(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    raw = {
        "version": "1.182.1",
        "engine_requested": "OSS",
        "results": [
            {
                "check_id": "experimental.javascript-eval-taint",
                "path": "src/synthetic.ts",
                "start": {"line": 5, "col": 2},
                "end": {"line": 5, "col": 8},
                "extra": {
                    "message": f"private tool message {CANARY}",
                    "severity": "ERROR",
                    "engine_kind": "OSS",
                    "lines": f"eval('{CANARY}')",
                },
            }
        ],
        "errors": [],
    }
    parsed = _parse_semgrep_json_internal(json.dumps(raw).encode(), target)
    finding = parsed.parsed.findings[0]
    evidence = build_taint_evidence(
        parsed.document, parsed.result_findings, target,
        rules_file=TAINT_RULE, trusted_rules_directory=RULES,
    )
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    return finding, evidence, scan


def _pattern(number: int = 1, *, path: str = "src/synthetic.ts") -> Finding:
    return Finding(
        finding_id=f"semgrep:{number:024x}",
        rule_id="baseline.javascript-dynamic-eval",
        title=f"private title {CANARY}",
        description=f"private description {CANARY}",
        severity=Severity.HIGH,
        source_tool="semgrep",
        file_path=path,
        line_number=5,
        evidence=f"eval('{CANARY}')",
    )


def test_markdown_taint_report_uses_consumer_claims_and_preserves_limits(tmp_path: Path) -> None:
    finding, evidence, scan = _taint_case(tmp_path)
    output = markdown_report.render_markdown_review(
        scan, evidence, rules_file=TAINT_RULE, trusted_rules_directory=RULES
    )
    assert "# AI Code Security Analyzer — Analyst Review Report" in output
    assert "취약점 확정 보고서가 아니며" in output
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." in output
    assert "실제 Source 위치" in output and "현재 자료에서 확인 불가" in output
    assert "구조화된 데이터 흐름 trace가 제공되지 않았습니다" in output
    assert "취약점 확정" in output
    assert "분석가 검토 작업" in output
    assert "전체 Finding 수: 1건" in output
    assert "표시된 Finding 수: 1건" in output
    assert "생략된 Finding 수: 0건" in output
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.confirmation is None
    assert CANARY not in output


def test_pattern_markdown_does_not_promote_to_taint_and_matches_review_claim_sets() -> None:
    finding = _pattern()
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    markdown = markdown_report.render_markdown_review(scan, (), rules_file=RULES / "security-baseline.yml", trusted_rules_directory=RULES)
    text = review.render_review(scan, (), rules_file=RULES / "security-baseline.yml", trusted_rules_directory=RULES)
    assert "일반 패턴" in markdown
    assert "Semgrep이 해당 규칙 매치를 보고했습니다." in markdown
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in markdown
    assert "신뢰된 taint 규칙 매치 보고" in markdown
    assert "취약점이 확인됐습니다" not in markdown
    assert "Semgrep이 해당 규칙 매치를 보고했습니다." in text


def test_markdown_escapes_untrusted_markdown_html_controls_and_long_labels() -> None:
    payload = "src/# title\n![x](evil) <img src=x onerror=alert(1)> ```\x1b[31m\u202e"
    finding = _pattern(path=payload).model_copy(update={"rule_id": payload})
    output = markdown_report.render_markdown_review(
        ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1"), ()
    )
    assert f"`{payload}`" not in output
    assert "<img" not in output
    assert "&lt;img" in output
    assert "\\u000a" in output
    assert "\\u0060\\u0060\\u0060" in output
    assert "\x1b" not in output
    assert "![x](evil)" in output  # confined to the escaped inline-code path
    location = output.split("- Semgrep 매치 위치:", 1)[1].split(" (상대 경로)", 1)[0]
    assert location.startswith(" `src/") and location.endswith("`:5")
    assert "\\u000a" in location
    assert len((output + "\n").encode("utf-8")) <= markdown_report.MAX_MARKDOWN_OUTPUT_BYTES

    long_finding = _pattern(path="src/" + ("x" * 800))
    long_output = markdown_report.render_markdown_review(
        ScanResult(ScanStatus.COMPLETED, (long_finding,), (), 0, "1.182.1"), ()
    )
    assert "…" in long_output


def test_markdown_failed_scan_does_not_show_supported_claims(tmp_path: Path) -> None:
    finding, evidence, scan = _taint_case(tmp_path)
    failed = replace(scan, status=ScanStatus.TIMED_OUT, issues=("semgrep_timeout",))
    output = markdown_report.render_markdown_review(
        failed, evidence, rules_file=TAINT_RULE, trusted_rules_directory=RULES
    )
    assert "시간 초과" in output
    assert "검사 실패" in output
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in output
    assert "확인된 근거를 표시할 수 없습니다" in output


def test_consumer_failure_hides_claims_in_markdown(tmp_path: Path, monkeypatch) -> None:
    _, evidence, scan = _taint_case(tmp_path)

    def reject(*_args, **_kwargs):
        raise EvidenceConsumerError("synthetic private exception")

    monkeypatch.setattr(review, "consume_evidence_summary", reject)
    output = markdown_report.render_markdown_review(
        scan, evidence, rules_file=TAINT_RULE, trusted_rules_directory=RULES
    )
    assert "근거 검증: **실패**" in output
    assert "synthetic private exception" not in output
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in output


def test_unclassified_markdown_does_not_upgrade_rule_hash_mismatch(tmp_path: Path) -> None:
    finding, evidence, scan = _taint_case(tmp_path)
    changed = (replace(evidence[0], rules_file_sha256="0" * 64),)
    output = markdown_report.render_markdown_review(
        scan, changed, rules_file=TAINT_RULE, trusted_rules_directory=RULES
    )
    assert "분류되지 않음" in output
    assert "규칙 파일의 해시가 예상값과 다릅니다." in output
    assert "취약점 확정 보고서가 아닙니다" not in output  # no such certainty phrase is synthesized
    assert finding.status is FindingStatus.UNVERIFIED


def test_markdown_zero_and_partial_scan_keep_status_limits() -> None:
    zero = markdown_report.render_markdown_review(ScanResult(ScanStatus.COMPLETED, (), (), 0, "1.182.1"))
    assert "전체 Finding 수: 0" in zero
    assert "표시된 Finding 수: 0건" in zero
    assert "생략된 Finding 수: 0건" in zero
    assert "코드가 안전하다는 뜻은 아닙니다" in zero
    partial = markdown_report.render_markdown_review(
        ScanResult(ScanStatus.PARTIAL, (), ("semgrep_skipped_paths",), 0, "1.182.1")
    )
    assert "부분 검사" in partial
    assert "전체 검사가 완료되지 않았습니다" in partial


@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.EXECUTION_FAILED,
        ScanStatus.TIMED_OUT,
        ScanStatus.INVALID_JSON,
        ScanStatus.OUTPUT_LIMIT_EXCEEDED,
        ScanStatus.NOT_INSTALLED,
    ],
)
def test_nonreviewable_scan_states_never_show_supported_claims(tmp_path: Path, status: ScanStatus) -> None:
    finding, evidence, scan = _taint_case(tmp_path / status.value)
    failed = replace(scan, status=status, issues=("semgrep_timeout",))
    output = markdown_report.render_markdown_review(
        failed, evidence, rules_file=TAINT_RULE, trusted_rules_directory=RULES
    )
    assert review._STATUS_LABEL[status] in output
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in output
    assert "확인된 근거를 표시할 수 없습니다" in output
    assert finding.status is FindingStatus.UNVERIFIED


def test_markdown_reports_finding_and_byte_omissions(monkeypatch) -> None:
    findings = tuple(_pattern(index) for index in range(1, 4))
    scan = ScanResult(ScanStatus.COMPLETED, findings, (), 0, "1.182.1")
    monkeypatch.setattr(markdown_report, "MAX_MARKDOWN_FINDINGS", 1)
    output = markdown_report.render_markdown_review(scan)
    assert "전체 Finding 수: 3" in output
    assert "표시된 Finding 수: 1" in output
    assert "생략된 Finding 수: 2" in output
    assert "생략 항목의 개별 검증 상태는 확인할 수 없으며" in output

    monkeypatch.setattr(markdown_report, "MAX_MARKDOWN_OUTPUT_BYTES", 1024)
    output = markdown_report.render_markdown_review(scan)
    assert len((output + "\n").encode("utf-8")) <= 1024
    assert "생략된 Finding 수" in output
