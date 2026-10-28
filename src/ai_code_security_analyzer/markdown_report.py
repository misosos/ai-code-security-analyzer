"""Source-free Markdown analyst report built from revalidated evidence."""

from __future__ import annotations

import html
import re
import unicodedata
from pathlib import Path

from ai_code_security_analyzer import review
from ai_code_security_analyzer.evidence_summary import FindingKind
from ai_code_security_analyzer.models import Finding, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.taint_evidence import TaintEvidence


MAX_MARKDOWN_FINDINGS = review.MAX_REVIEW_FINDINGS
MAX_MARKDOWN_OUTPUT_BYTES = 512 * 1024
_VERSION = re.compile(r"\A\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")
_MAX_LABEL_LENGTH = 512


def _safe_code(value: object, *, identifier: bool = False) -> str:
    """Render an untrusted label as inert inline code, escaping Markdown delimiters."""
    if not isinstance(value, str):
        return "`확인 불가`"
    if identifier and not review._SAFE_IDENTIFIER.fullmatch(value):
        return "`확인 불가`"
    clipped = value[:_MAX_LABEL_LENGTH]
    if len(value) > _MAX_LABEL_LENGTH:
        clipped += "…"
    safe: list[str] = []
    for char in clipped:
        category = unicodedata.category(char)
        if char == "`":
            safe.append("\\u0060")
        elif char == "\\":
            safe.append("\\u005c")
        elif category.startswith("C") or category in {"Zl", "Zp"}:
            safe.append(f"\\u{ord(char):04x}")
        else:
            safe.append(char)
    return "`" + html.escape("".join(safe), quote=False) + "`"


def _scan_overview(scan: ScanResult) -> list[str]:
    status = review._STATUS_LABEL.get(scan.status, "확인 불가")
    findings = tuple(item for item in scan.findings if isinstance(item, Finding))
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        if isinstance(finding.severity, Severity):
            counts[finding.severity] += 1
    version = scan.semgrep_version if isinstance(scan.semgrep_version, str) and _VERSION.fullmatch(scan.semgrep_version) else "확인 불가"
    complete = scan.status is ScanStatus.COMPLETED
    lines = [
        "## 검사 개요",
        "",
        f"- 검사 상태: **{status}**",
        f"- 검사 완료: **{'예' if complete else '아니요'}**",
        f"- Semgrep 버전: {_safe_code(version)}",
        f"- 전체 Finding 수: {len(scan.findings)} (취약점 확정 수가 아님)",
        f"- 심각도별 Finding: {', '.join(f'{severity.value} {counts[severity]}건' for severity in Severity)}",
        f"- 검사 진단 항목: {len(scan.issues)}건",
    ]
    if scan.status is ScanStatus.PARTIAL:
        lines.extend(["", "> 주의: 일부 경로 또는 규칙이 누락될 수 있어 전체 검사가 완료되지 않았습니다."])
    elif scan.status not in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}:
        lines.extend(["", "> **검사 실패:** 아래 결과를 정상 완료된 분석으로 신뢰하지 마세요."])
    safe_issues = []
    for issue in scan.issues:
        label = review._ISSUE_LABEL.get(issue) if isinstance(issue, str) else None
        if label and label not in safe_issues:
            safe_issues.append(label)
    if safe_issues:
        lines.extend(["", "검사 안내: " + "; ".join(safe_issues[:10])])
        if len(safe_issues) > 10:
            lines.append(f"추가 검사 안내 생략: {len(safe_issues) - 10}건")
    lines.extend(
        [
            "",
            "### 공통 해석 제한",
            "",
            "- Finding은 별도 확인이 필요한 정적 분석 후보이며 취약점 확정이 아닙니다.",
            "- Finding이 0건이어도 대상 코드가 안전하다는 뜻은 아닙니다.",
            "- 이 보고서는 실제 악용 가능성이나 런타임 도달 여부를 검증하지 않습니다.",
            "- 규칙 파일의 현재 해시 일치는 Semgrep 실행 시점의 규칙 바이트 동일성을 증명하지 않습니다.",
            "- 분석 대상 소스 파일이 검사 시점 이후 변경되지 않았음을 증명하지 않습니다.",
            "- 외부 공유 전 경로와 규칙 식별자 등 저장소 정보를 사람이 검토하세요.",
        ]
    )
    return lines


def _finding_section(
    number: int,
    finding: Finding,
    scan: ScanResult,
    evidence_items: tuple[TaintEvidence, ...],
    *,
    rules_file: Path | None,
    trusted_rules_directory: Path | None,
) -> list[str]:
    lines = [f"## 검토 대상 #{number} (표시 순서이며 위험 순위가 아님)", ""]
    lines.extend(
        [
            f"- Finding ID: {_safe_code(finding.finding_id, identifier=True)}",
            f"- 규칙 ID: {_safe_code(finding.rule_id, identifier=True)}",
            f"- Semgrep 심각도 분류: **{review._SEVERITY_LABEL.get(finding.severity, '확인 불가')}** (실제 악용 가능성 판정은 아님)",
            f"- 검증 상태: **{review._FINDING_STATUS_LABEL.get(finding.status, '확인 불가')}**",
        ]
    )
    if review._safe_relative_path(finding.file_path):
        line = str(finding.line_number) if type(finding.line_number) is int and finding.line_number > 0 else "?"
        location = f"{_safe_code(finding.file_path)}:{line} (상대 경로)"
    else:
        location = "안전한 상대 경로가 아니어서 숨김"
    lines.append(f"- Semgrep 매치 위치: {location}")

    reviewable = scan.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}
    validated = None
    if reviewable:
        try:
            validated = review._consume_one(
                finding,
                scan,
                evidence_items,
                rules_file=rules_file,
                trusted_rules_directory=trusted_rules_directory,
            )
        except Exception:
            validated = None
    if validated is None:
        failure_code = "review_evidence_validation_failed" if reviewable else "scan_not_reviewable"
        lines.extend(
            [
                "- 탐지 유형: **검증 불가**",
                f"- 근거 검증: **실패** (`{failure_code}`)",
                "- 확인된 근거: 표시할 수 없습니다.",
                "",
                "### 확인된 근거",
                "",
                "- 확인된 근거를 표시할 수 없습니다.",
                "",
                "### 제한된 근거",
                "",
                "- 검사 상태 또는 근거 연결을 검증할 수 없습니다. 취약점 없음이나 오탐을 뜻하지 않습니다.",
            ]
        )
        return lines

    lines.extend(
        [
            f"- 탐지 유형: **{review._KIND_LABEL[validated.finding_kind]}**",
            "- 근거 검증: **통과** (현재 입력의 구조적 연결만 확인; 취약점 의미를 검증한 것은 아님)",
            "",
            "### 확인된 근거",
            "",
        ]
    )
    if validated.allowed_claims:
        for claim in validated.allowed_claims:
            statement = review._CLAIM_TEXT.get(claim.claim_type, "확인된 구조적 근거가 있습니다.")
            sources = ", ".join(review._SOURCE_LABEL[item] for item in claim.evidence_provenance) or "출처 정보 없음"
            lines.append(f"- {statement} (출처: {sources})")
    else:
        lines.append("- 허용된 근거 주장이 없습니다.")
    lines.extend(["", "### 제한된 근거", ""])
    for claim in validated.restricted_claims:
        label = review._CLAIM_LABEL.get(claim.claim_type, "확인 대상")
        decision = review._DECISION_LABEL.get(claim.decision, "판정 불가")
        reasons = review._reason_text(claim)
        lines.append(f"- **{label}** — {decision}. {reasons}")
    if not validated.restricted_claims:
        lines.append("- 제한된 주장이 없습니다.")

    limitation_reasons = {
        reason for claim in validated.restricted_claims for reason in claim.reason_codes
    }
    remaining = tuple(dict.fromkeys(reason for reason in validated.limitations if reason not in limitation_reasons))
    if remaining:
        lines.extend(["", "### 추가 분석 한계", ""])
        for reason in remaining:
            lines.append(f"- {review._REASON_LABEL.get(reason, '추가 검토가 필요합니다.')}")

    lines.extend(["", "### 분석가 검토 작업", ""])
    for title, description in review._TASKS[validated.finding_kind]:
        lines.append(f"- **{title}:** {description} (미완료 상태의 검토 제안)")
    return lines


def render_markdown_review(
    scan: ScanResult,
    evidence_items: tuple[TaintEvidence, ...] = (),
    *,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> str:
    """Render a bounded Markdown review using the same Gate/Consumer policy as Review View."""
    if not isinstance(scan, ScanResult):
        return "# AI Code Security Analyzer — Analyst Review Report\n\n검사 상태: 확인 불가\n\n보고서를 생성할 수 없습니다."

    findings = tuple(item for item in scan.findings if isinstance(item, Finding))
    base = [
        "# AI Code Security Analyzer — Analyst Review Report",
        "",
        "> 정적 분석 검토용 문서입니다. 취약점 확정 보고서가 아니며 Finding은 별도 확인이 필요한 후보입니다.",
        "",
        *_scan_overview(scan),
        "",
        "## Finding 검토",
        "",
        "검토 번호는 표시 순서이며 위험 순위가 아닙니다.",
        "",
    ]
    eligible = findings[:MAX_MARKDOWN_FINDINGS]
    cards: list[list[str]] = []
    for index, finding in enumerate(eligible, start=1):
        cards.append(
            _finding_section(
                index,
                finding,
                scan,
                evidence_items if isinstance(evidence_items, tuple) else (),
                rules_file=rules_file,
                trusted_rules_directory=trusted_rules_directory,
            )
        )

    displayed: list[list[str]] = []
    for card in cards:
        candidate_cards = [*displayed, card]
        omitted = len(findings) - len(candidate_cards)
        suffix = _omission_section(omitted, len(findings))
        candidate = "\n".join([*base, *[line for section in candidate_cards for line in section], *suffix])
        if len((candidate + "\n").encode("utf-8")) > MAX_MARKDOWN_OUTPUT_BYTES:
            break
        displayed.append(card)

    omitted = len(findings) - len(displayed)
    suffix = _omission_section(omitted, len(findings))
    output = "\n".join([*base, *[line for section in displayed for line in section], *suffix]).rstrip()
    while len((output + "\n").encode("utf-8")) > MAX_MARKDOWN_OUTPUT_BYTES and displayed:
        displayed.pop()
        omitted = len(findings) - len(displayed)
        suffix = _omission_section(omitted, len(findings))
        output = "\n".join([*base, *[line for section in displayed for line in section], *suffix]).rstrip()
    if len((output + "\n").encode("utf-8")) > MAX_MARKDOWN_OUTPUT_BYTES:
        output = _compact_fallback(scan, len(findings))
    return output


def _omission_section(count: int, total: int) -> list[str]:
    return [
        "",
        "## 출력 범위",
        "",
        f"- 전체 Finding 수: {total}건",
        f"- 표시된 Finding 수: {total - count}건",
        f"- 생략된 Finding 수: {count}건",
        *(
            ["- 생략 항목의 개별 검증 상태는 확인할 수 없으며 안전하다고 판단할 수 없습니다."]
            if count
            else []
        ),
    ]


def _compact_fallback(scan: ScanResult, finding_count: int) -> str:
    status = review._STATUS_LABEL.get(scan.status, "확인 불가")
    return (
        "# AI Code Security Analyzer — Analyst Review Report\n\n"
        "> 정적 분석 검토용 문서입니다. 취약점 확정 보고서가 아닙니다.\n\n"
        f"- 검사 상태: {status}\n"
        f"- 전체 Finding 수: {finding_count}건 (취약점 확정 수가 아님)\n"
        "- 표시된 Finding 수: 0건\n"
        f"- 생략된 Finding 수: {finding_count}건 (보고서 크기 제한)\n"
        "- 생략 항목의 개별 검증 상태는 확인할 수 없습니다."
    )
