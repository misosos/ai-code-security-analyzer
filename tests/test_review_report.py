"""Synthetic user-facing review output tests; no model or network calls."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ai_code_security_analyzer import cli, review
from ai_code_security_analyzer.evidence_consumer import EvidenceConsumerError
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus, _ScanOutput
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import build_taint_evidence


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
CANARY = "SYNTHETIC_REVIEW_SECRET_CANARY"


def _finding(
    *,
    number: int = 1,
    rule_id: str = "baseline.javascript-dynamic-eval",
    path: str = "src/synthetic.ts",
    title: str = "Synthetic pattern title",
) -> Finding:
    return Finding(
        finding_id=f"semgrep:{number:024x}",
        rule_id=rule_id,
        title=title,
        description=f"private synthetic description {CANARY}",
        severity=Severity.HIGH,
        source_tool="semgrep",
        file_path=path,
        line_number=5,
        evidence=f"private code snippet {CANARY}",
    )


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
                    "message": f"private Semgrep message {CANARY}",
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
        parsed.document,
        parsed.result_findings,
        target,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    return finding, evidence, scan


def test_review_cli_is_opt_in_and_uses_one_internal_scan(tmp_path: Path, monkeypatch, capsys) -> None:
    target = tmp_path / "target"
    target.mkdir()
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    rule = trusted / "rules.yml"
    rule.write_text("rules: []\n")
    finding = _finding()
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    calls = []

    def scan_with_evidence(self, passed_target, passed_rule):
        calls.append((passed_target, passed_rule))
        return _ScanOutput(scan)

    monkeypatch.setattr(cli.SemgrepAdapter, "_scan_with_evidence", scan_with_evidence)
    monkeypatch.setattr(
        cli.SemgrepAdapter,
        "scan",
        lambda *_args, **_kwargs: pytest.fail("review must not run Semgrep twice"),
    )
    result = cli.main(["scan", "--path", str(target), "--rules", str(rule), "--format", "review"])
    output = capsys.readouterr()
    assert result == cli.EXIT_COMPLETE
    assert len(calls) == 1
    assert "검토용 분석 결과" in output.out
    assert "검토 대상 #1" in output.out
    assert output.err == ""


def test_review_rejects_output_file_and_preserves_existing_exit_code(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    rule = trusted / "rules.yml"
    rule.write_text("rules: []\n")
    monkeypatch.setattr(
        cli.SemgrepAdapter,
        "_scan_with_evidence",
        lambda *_args, **_kwargs: pytest.fail("scan must not run when output policy rejects"),
    )
    status = cli.main(
        ["scan", "--path", str(target), "--rules", str(rule), "--format", "review", "--output", str(tmp_path / "r")]
    )
    captured = capsys.readouterr()
    assert status == cli.EXIT_INVALID_INPUT
    assert "requires --format json" in captured.err
    assert captured.out == ""


@pytest.mark.parametrize(
    ("scan_status", "expected_exit"),
    [
        (ScanStatus.PARTIAL, cli.EXIT_PARTIAL),
        (ScanStatus.TIMED_OUT, cli.EXIT_FAILED),
    ],
)
def test_review_keeps_existing_cli_exit_code_policy(
    tmp_path: Path, monkeypatch, capsys, scan_status: ScanStatus, expected_exit: int
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    rule = trusted / "rules.yml"
    rule.write_text("rules: []\n")
    finding = _finding()
    scan = ScanResult(scan_status, (finding,), (), 0, "1.182.1")
    monkeypatch.setattr(cli.SemgrepAdapter, "_scan_with_evidence", lambda *_args: _ScanOutput(scan))
    status = cli.main(["scan", "--path", str(target), "--rules", str(rule), "--format", "review"])
    output = capsys.readouterr().out
    assert status == expected_exit
    assert "검사 완료: 아니요" in output


def test_review_shows_only_consumer_supported_claims_and_fixed_review_tasks(tmp_path: Path) -> None:
    finding, evidence, scan = _taint_case(tmp_path)
    output = review.render_review(
        scan,
        evidence,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." in output
    assert "규칙에 Source 패턴이 선언되어 있습니다." in output
    assert "확인 항목: 실제 Source 위치 식별 [현재 자료에서 확인 불가]" in output
    assert "확인 항목: Sink 인자 위치 식별 [현재 자료에서 확인 불가]" in output
    assert "확인 항목: 전체 데이터 흐름 경로 제공 [현재 자료에서 확인 불가]" in output
    assert "확인 항목: 취약점 확정 [이 분석에서 지원하지 않는 판단]" in output
    assert "전체 Source→Sink 경로는 증명되지 않았습니다." in output
    assert "검사 시점에 사용된 규칙 파일의 원자적 동일성은 증명되지 않았습니다." in output
    assert "실제 입력 출처를 코드에서 확인" in output
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.confirmation is None


def test_review_keeps_pattern_unclassified_and_scan_limits_distinct(tmp_path: Path) -> None:
    pattern = _finding()
    pattern_output = review.render_review(
        ScanResult(ScanStatus.COMPLETED, (pattern,), (), 0, "1.182.1"),
        (),
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert "탐지 유형: 일반 패턴" in pattern_output
    assert "확인 항목: 신뢰된 taint 규칙 매치 보고 [현재 자료에서 확인 불가]" in pattern_output

    timed_out = review.render_review(
        ScanResult(ScanStatus.TIMED_OUT, (pattern,), ("semgrep_timeout",), None, "1.182.1"),
        (),
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert "검사 상태: 시간 초과" in timed_out
    assert "검사 실패 상태에서는 근거를 검증된 사실로 표시하지 않습니다" in timed_out
    assert "Semgrep이 해당 규칙 매치를 보고했습니다." not in timed_out

    taint_finding, taint_evidence, taint_scan = _taint_case(tmp_path / "unclassified")
    changed_evidence = (replace(taint_evidence[0], rules_file_sha256="0" * 64),)
    unclassified = review.render_review(
        taint_scan,
        changed_evidence,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert "탐지 유형: 분류되지 않음" in unclassified
    assert "규칙 파일의 해시가 예상값과 다릅니다." in unclassified


def test_review_zero_findings_does_not_claim_safety() -> None:
    output = review.render_review(ScanResult(ScanStatus.COMPLETED, (), (), 0, "1.182.1"), ())
    assert "검토 대상: 0건" in output
    assert "대상 코드가 안전하다는 뜻은 아닙니다" in output


def test_review_never_shows_claims_from_nonreviewable_scan(tmp_path: Path) -> None:
    _, evidence, completed = _taint_case(tmp_path)
    timed_out = replace(completed, status=ScanStatus.TIMED_OUT)
    output = review.render_review(
        timed_out,
        evidence,
        rules_file=TAINT_RULE,
        trusted_rules_directory=RULES,
    )
    assert "근거 검증: 실패 (scan_not_reviewable)" in output
    assert "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다." not in output
    assert "확인된 사실: 표시할 수 없습니다." in output


def test_review_isolates_consumer_failure_without_emitting_claims(
    tmp_path: Path, monkeypatch
) -> None:
    first = _finding(number=1)
    second = _finding(number=2, path="src/other.ts")
    scan = ScanResult(ScanStatus.COMPLETED, (first, second), (), 0, "1.182.1")
    real_consume = review.consume_evidence_summary

    def fail_first(summary, finding, **kwargs):
        if finding.finding_id == first.finding_id:
            raise EvidenceConsumerError("evidence_consumer_rejected")
        return real_consume(summary, finding, **kwargs)

    monkeypatch.setattr(review, "consume_evidence_summary", fail_first)
    output = review.render_review(scan, ())
    first_card = output.split("검토 대상 #1", 1)[1].split("검토 대상 #2", 1)[0]
    second_card = output.split("검토 대상 #2", 1)[1]
    assert "근거 검증: 실패" in first_card
    assert "Semgrep이 해당 규칙 매치를 보고했습니다." not in first_card
    assert "근거 검증: 통과" in second_card
    assert "근거를 확인 사실로 표시하지 않은 Finding: 1건" in output


def test_review_escapes_terminal_controls_and_hides_untrusted_finding_text(tmp_path: Path) -> None:
    malicious = _finding(
        path="src/evil\x1b[31m\nstatus-done.ts",
        title=f"title {CANARY}",
    )
    output = review.render_review(
        ScanResult(ScanStatus.COMPLETED, (malicious,), (), 0, "1.182.1"),
        (),
    )
    assert "src/evil\\u001b[31m\\nstatus-done.ts" in output
    assert CANARY not in output
    assert output.count("검사 상태:") == 1


def test_review_hides_absolute_or_traversing_finding_path() -> None:
    for path in ("/private/synthetic.ts", "../outside.ts", "file:///tmp/synthetic.ts"):
        finding = _finding(path=path)
        output = review.render_review(
            ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1"),
            (),
        )
        assert path not in output
        assert "안전한 상대 경로가 아니어서 숨김" in output


def test_review_hides_unsafe_rule_identifiers() -> None:
    finding = _finding(rule_id="/private/path/SYNTHETIC_REVIEW_SECRET_CANARY")
    output = review.render_review(
        ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1"),
        (),
    )
    assert "규칙 ID: 확인 불가" in output
    assert "/private/path" not in output
    assert CANARY not in output


def test_review_does_not_echo_unvalidated_finding_id() -> None:
    finding = _finding().model_copy(update={"finding_id": CANARY})
    output = review.render_review(
        ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1"),
        (),
    )
    assert CANARY not in output
    assert "Finding ID: 확인 불가" in output


def test_review_escapes_bidi_format_characters() -> None:
    finding = _finding(path="src/file\u202eevil.ts")
    output = review.render_review(
        ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1"),
        (),
    )
    assert "\\u202e" in output
    assert "\u202e" not in output


def test_review_output_limit_reports_omitted_findings(tmp_path: Path, monkeypatch) -> None:
    findings = tuple(_finding(number=n) for n in range(1, 4))
    scan = ScanResult(ScanStatus.COMPLETED, findings, (), 0, "1.182.1")
    monkeypatch.setattr(review, "MAX_REVIEW_FINDINGS", 1)
    output = review.render_review(scan, ())
    assert "검토 대상 #1" in output
    assert "검토 대상 #2" not in output
    assert "표시하지 않은 검토 대상: 2건" in output


def test_review_byte_limit_uses_explicit_summary_fallback(monkeypatch) -> None:
    finding = _finding()
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    monkeypatch.setattr(review, "MAX_REVIEW_OUTPUT_BYTES", 512)
    output = review.render_review(scan, ())
    assert "생략된 상세: 1건 (전체 보고서 바이트 제한)" in output
    assert "기존 text 또는 JSON 형식" in output
    assert len(output.encode("utf-8")) <= 512
