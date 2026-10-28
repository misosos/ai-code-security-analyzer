"""Fixed-template analyst review output based only on validated evidence."""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path, PurePosixPath

from ai_code_security_analyzer.evidence_consumer import (
    EvidenceConsumerError,
    ValidatedEvidence,
    consume_evidence_summary,
)
from ai_code_security_analyzer.evidence_sufficiency import (
    ClaimDecision,
    ClaimType,
    EvidenceReason,
    EvidenceSource,
)
from ai_code_security_analyzer.evidence_summary import (
    FindingKind,
    build_evidence_summary,
)
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.taint_evidence import TaintEvidence


MAX_REVIEW_FINDINGS = 50
MAX_REVIEW_OUTPUT_BYTES = 512 * 1024
MAX_LABEL_LENGTH = 512
_VERSION = re.compile(r"\A\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")
_SAFE_IDENTIFIER = re.compile(r"\A[A-Za-z0-9_.:-]{1,256}\Z")


_STATUS_LABEL = {
    ScanStatus.COMPLETED: "정상 완료",
    ScanStatus.PARTIAL: "부분 검사",
    ScanStatus.EXECUTION_FAILED: "실행 실패",
    ScanStatus.TIMED_OUT: "시간 초과",
    ScanStatus.INVALID_JSON: "결과 형식 오류",
    ScanStatus.OUTPUT_LIMIT_EXCEEDED: "출력 제한 초과",
    ScanStatus.NOT_INSTALLED: "Semgrep 미설치",
}
_ISSUE_LABEL = {
    "semgrep_reported_errors": "Semgrep 오류가 보고됨",
    "semgrep_skipped_rules": "일부 규칙을 건너뜀",
    "semgrep_skipped_paths": "일부 경로를 건너뜀",
    "no_files_scanned": "검사한 파일이 없음",
    "semgrep_not_installed": "Semgrep이 설치되지 않음",
    "version_check_failed": "Semgrep 버전 확인 실패",
    "required_option_unsupported": "필수 안전 옵션을 사용할 수 없음",
    "semgrep_timeout": "검사 시간 제한에 도달함",
    "semgrep_output_limit": "검사 출력 제한에 도달함",
    "semgrep_launch_failed": "Semgrep 실행 실패",
    "invalid_json": "Semgrep 결과 형식을 읽을 수 없음",
    "nonzero_exit": "Semgrep이 오류 상태로 종료됨",
}
_KIND_LABEL = {
    FindingKind.PATTERN: "일반 패턴",
    FindingKind.TAINT: "taint 규칙 (정의된 입력 흐름을 검사하는 규칙)",
    FindingKind.UNCLASSIFIED: "분류되지 않음",
}
_SEVERITY_LABEL = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}
_FINDING_STATUS_LABEL = {
    FindingStatus.UNVERIFIED: "미검증 후보 (취약점·오탐 모두 미확정)",
    FindingStatus.CONFIRMED: "확인됨 (기존 Finding 기록; 이 화면에서 판정하지 않음)",
    FindingStatus.FALSE_POSITIVE: "오탐 확인됨 (기존 Finding 기록; 이 화면에서 판정하지 않음)",
}
_CLAIM_TEXT = {
    ClaimType.MATCH_REPORTED: "Semgrep이 해당 규칙 매치를 보고했습니다.",
    ClaimType.TAINT_RULE_MATCH_REPORTED: "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다.",
    ClaimType.SOURCE_PATTERN_DECLARED: "신뢰된 규칙에 Source 패턴이 선언되어 있습니다.",
    ClaimType.SINK_PATTERN_DECLARED: "신뢰된 규칙에 Sink 패턴이 선언되어 있습니다.",
    ClaimType.MATCH_LOCATION_OBSERVED: (
        "Semgrep 결과의 매치 위치가 확인됐습니다. Sink 인자 위치라는 뜻은 아닙니다."
    ),
}
_CLAIM_LABEL = {
    ClaimType.MATCH_REPORTED: "Semgrep 규칙 매치 보고",
    ClaimType.TAINT_RULE_MATCH_REPORTED: "신뢰된 taint 규칙 매치 보고",
    ClaimType.SOURCE_PATTERN_DECLARED: "규칙의 Source 패턴 선언",
    ClaimType.SINK_PATTERN_DECLARED: "규칙의 Sink 패턴 선언",
    ClaimType.MATCH_LOCATION_OBSERVED: "Semgrep 매치 위치 관찰",
    ClaimType.SOURCE_LOCATION_IDENTIFIED: "실제 Source 위치 식별",
    ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED: "Sink 인자 위치 식별",
    ClaimType.FLOW_TRACE_AVAILABLE: "전체 데이터 흐름 경로 제공",
    ClaimType.SANITIZER_MATCH_OBSERVED: "Sanitizer 매치 관찰",
    ClaimType.SANITIZER_EFFECTIVENESS_VERIFIED: "Sanitizer 효과 검증",
    ClaimType.VULNERABILITY_CONFIRMED: "취약점 확정",
}
_DECISION_LABEL = {
    ClaimDecision.SUPPORTED: "근거로 지원됨",
    ClaimDecision.INSUFFICIENT_EVIDENCE: "근거 부족",
    ClaimDecision.UNAVAILABLE: "현재 자료에서 확인 불가",
    ClaimDecision.AMBIGUOUS: "근거 연결 모호",
    ClaimDecision.UNSUPPORTED_CLAIM: "이 분석에서 지원하지 않는 판단",
}
_SOURCE_LABEL = {
    EvidenceSource.SEMGREP_OBSERVATION: "Semgrep 관찰",
    EvidenceSource.TRUSTED_RULE_DECLARATION: "신뢰 규칙 선언",
    EvidenceSource.ANALYZER_DERIVED: "분석기 연결·정책 검사",
}
_REASON_LABEL = {
    EvidenceReason.SCAN_STATE_UNAVAILABLE: "검사 상태를 확인할 수 없습니다.",
    EvidenceReason.SCAN_PARTIAL: "검사가 일부만 완료됐습니다.",
    EvidenceReason.SCAN_NOT_COMPLETE: "전체 검사가 완료되지 않았습니다.",
    EvidenceReason.SCAN_FAILED: "검사가 실패해 매치를 확인할 수 없습니다.",
    EvidenceReason.SCAN_RESULT_INCONSISTENT: "검사 상태와 결과 정보가 일치하지 않습니다.",
    EvidenceReason.TAINT_EVIDENCE_MALFORMED: "taint 근거 구조가 올바르지 않습니다.",
    EvidenceReason.FINDING_NOT_IN_SCAN: "이 검사의 결과에서 Finding을 찾지 못했습니다.",
    EvidenceReason.FINDING_ASSOCIATION_AMBIGUOUS: "Finding과 근거의 연결이 모호합니다.",
    EvidenceReason.FINDING_ID_MISMATCH: "Finding 식별자가 일치하지 않습니다.",
    EvidenceReason.RULE_ID_MISMATCH: "규칙 식별자가 일치하지 않습니다.",
    EvidenceReason.FILE_PATH_MISMATCH: "근거 파일 위치가 일치하지 않습니다.",
    EvidenceReason.MATCH_LOCATION_UNAVAILABLE: "매치 위치를 확인할 수 없습니다.",
    EvidenceReason.MATCH_LOCATION_MALFORMED: "매치 위치 정보가 올바르지 않습니다.",
    EvidenceReason.MATCH_LOCATION_NOT_SINK_ARGUMENT: (
        "매치 위치는 Sink 인자 위치로 확인되지 않았습니다."
    ),
    EvidenceReason.TAINT_EVIDENCE_UNAVAILABLE: "연결된 taint 근거가 없습니다.",
    EvidenceReason.ENGINE_UNVERIFIED: "분석 엔진 정보를 확인할 수 없습니다.",
    EvidenceReason.RULE_DECLARATION_UNVERIFIED: "신뢰 규칙 선언을 확인할 수 없습니다.",
    EvidenceReason.RULE_HASH_MISMATCH: "현재 규칙 파일의 해시가 예상값과 다릅니다.",
    EvidenceReason.RULE_DECLARATION_MISMATCH: "규칙 선언과 근거 정보가 일치하지 않습니다.",
    EvidenceReason.SOURCE_PATTERN_NOT_DECLARED: "Source 패턴 선언이 없습니다.",
    EvidenceReason.SINK_PATTERN_NOT_DECLARED: "Sink 패턴 선언이 없습니다.",
    EvidenceReason.SOURCE_LOCATION_UNKNOWN: "실제 Source 위치 정보가 제공되지 않았습니다.",
    EvidenceReason.SOURCE_LOCATION_UNAVAILABLE: "실제 Source 위치를 확인할 수 없습니다.",
    EvidenceReason.SOURCE_LOCATION_MALFORMED: "Source 위치 정보가 올바르지 않습니다.",
    EvidenceReason.SOURCE_LOCATION_EVIDENCE_UNAVAILABLE: "Source 위치를 확인할 관찰 근거가 없습니다.",
    EvidenceReason.SINK_ARGUMENT_LOCATION_UNKNOWN: "Sink 인자 위치 정보가 제공되지 않았습니다.",
    EvidenceReason.SINK_ARGUMENT_LOCATION_UNAVAILABLE: "Sink 인자 위치를 확인할 수 없습니다.",
    EvidenceReason.SINK_ARGUMENT_LOCATION_MALFORMED: "Sink 인자 위치 정보가 올바르지 않습니다.",
    EvidenceReason.SINK_ARGUMENT_LOCATION_EVIDENCE_UNAVAILABLE: (
        "Sink 인자 위치를 확인할 관찰 근거가 없습니다."
    ),
    EvidenceReason.FLOW_TRACE_ABSENT: (
        "구조화된 데이터 흐름 trace가 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다."
    ),
    EvidenceReason.FLOW_TRACE_EMPTY: (
        "데이터 흐름 trace가 비어 있습니다. 흐름이 없다는 뜻은 아닙니다."
    ),
    EvidenceReason.FLOW_TRACE_UNSUPPORTED: "데이터 흐름 trace 형식을 지원하지 않습니다.",
    EvidenceReason.FLOW_TRACE_MALFORMED: "데이터 흐름 trace 구조가 올바르지 않습니다.",
    EvidenceReason.FLOW_TRACE_DETAILS_UNAVAILABLE: "검증 가능한 trace 단계 정보가 없습니다.",
    EvidenceReason.SANITIZER_PATTERN_NOT_DECLARED: "Sanitizer 패턴 선언이 없습니다.",
    EvidenceReason.SANITIZER_MATCH_UNKNOWN: "Sanitizer 적용 여부가 확인되지 않았습니다.",
    EvidenceReason.SANITIZER_MATCH_UNAVAILABLE: "Sanitizer 매치 정보를 확인할 수 없습니다.",
    EvidenceReason.SANITIZER_MATCH_MALFORMED: "Sanitizer 매치 정보가 올바르지 않습니다.",
    EvidenceReason.SANITIZER_MATCH_DETAILS_UNAVAILABLE: "Sanitizer 매치 위치 근거가 없습니다.",
    EvidenceReason.SANITIZER_EFFECTIVENESS_NOT_VERIFIED: (
        "정제 함수의 실제 보안 효과는 검증되지 않았습니다."
    ),
    EvidenceReason.INDEPENDENT_CONFIRMATION_REQUIRED: "취약점 확정에는 독립적인 확인이 필요합니다.",
    EvidenceReason.RULE_FILE_SCAN_TIME_UNPROVEN: (
        "검사 시점에 사용된 규칙 파일의 원자적 동일성은 증명되지 않았습니다."
    ),
    EvidenceReason.ANALYSIS_SCOPE_DERIVED: (
        "분석 범위는 엔진 메타데이터를 바탕으로 추정됐습니다."
    ),
    EvidenceReason.TAINT_MATCH_NOT_CONFIRMATION: "taint 규칙 매치는 취약점 확정이 아닙니다.",
    EvidenceReason.SOURCE_SINK_PATH_UNPROVEN: "전체 Source→Sink 경로는 증명되지 않았습니다.",
    EvidenceReason.SANITIZER_MATCH_NOT_EFFECTIVENESS: (
        "Sanitizer 매치만으로 정제 효과가 증명되지는 않습니다."
    ),
    EvidenceReason.DECLARATION_NOT_OBSERVATION: "규칙 선언은 실제 코드 위치의 관찰이 아닙니다.",
    EvidenceReason.STATIC_EVIDENCE_CANNOT_SUPPORT_CLAIM: (
        "현재 정적 근거로는 이 주장을 지원할 수 없습니다."
    ),
}
_TASKS = {
    FindingKind.TAINT: (
        (
            "실제 입력 출처를 코드에서 확인",
            "요청값 등 외부 입력이 어디서 만들어지는지 직접 확인하세요.",
        ),
        (
            "위험 함수에 전달되는 값 확인",
            "매치 위치의 인자와 변수 대입 관계를 코드에서 추적하세요.",
        ),
        (
            "입력 검증과 정제 로직 확인",
            "검증 분기와 정제 함수 구현·호출 순서를 확인하세요.",
        ),
        (
            "함수 경계 밖의 데이터 흐름 검토",
            "다른 함수와 파일의 전달 관계는 이 결과에서 확인되지 않습니다.",
        ),
        ("런타임 도달 조건 확인", "실행 조건과 입력 제약을 별도로 검토하세요."),
    ),
    FindingKind.PATTERN: (
        (
            "탐지된 패턴이 실제 코드인지 확인",
            "표시된 상대 경로와 줄에서 호출 형태를 직접 확인하세요.",
        ),
        ("위험 함수의 입력값 확인", "상수인지 외부 입력인지 코드에서 확인하세요."),
        ("주변 방어 조건 확인", "검증·정제 로직이 실제로 적용되는지 검토하세요."),
    ),
    FindingKind.UNCLASSIFIED: (
        (
            "규칙 선언과 분석 결과 연결 확인",
            "현재 근거만으로 탐지 유형을 분류할 수 없습니다.",
        ),
        ("매치 위치와 규칙 ID 확인", "원본 프로젝트에서 표시된 위치를 직접 확인하세요."),
        ("누락된 근거 정보 확인", "Source, Sink, trace 정보가 제공됐는지 별도로 확인하세요."),
    ),
}


class _ReviewRejected(ValueError):
    pass


def _escaped(value: object, *, limit: int = MAX_LABEL_LENGTH) -> str:
    if not isinstance(value, str):
        return "확인 불가"
    clipped = value[:limit]
    if len(value) > limit:
        clipped += "…"
    safe = "".join(
        f"\\u{ord(char):04x}"
        if unicodedata.category(char) in {"Cf", "Cs", "Zl", "Zp"}
        else char
        for char in clipped
    )
    return json.dumps(safe, ensure_ascii=False)[1:-1]


def _safe_relative_path(value: object) -> bool:
    if not isinstance(value, str):
        return False
    path = PurePosixPath(value)
    return (
        bool(value)
        and len(value) <= 4096
        and not path.is_absolute()
        and ".." not in path.parts
        and ":" not in value
        and "\\" not in value
    )


def _safe_identifier(value: object) -> str:
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
        return "확인 불가"
    return value


def _severity_counts(scan: ScanResult) -> dict[Severity, int]:
    counts = {severity: 0 for severity in Severity}
    for item in scan.findings:
        if isinstance(item, Finding) and isinstance(item.severity, Severity):
            counts[item.severity] += 1
    return counts


def _evidence_for_finding(
    finding: Finding, evidence_items: tuple[TaintEvidence, ...]
) -> TaintEvidence | None:
    candidates = [
        item
        for item in evidence_items
        if isinstance(item, TaintEvidence) and item.rule_id == finding.rule_id
    ]
    by_id = [item for item in candidates if item.finding_id == finding.finding_id]
    if len(by_id) == 1:
        return by_id[0]
    if len(by_id) > 1:
        raise _ReviewRejected("finding_association_ambiguous")

    by_location = [
        item
        for item in candidates
        if item.matched_file == finding.file_path
        and item.matched_start is not None
        and item.matched_start.line == finding.line_number
        and item.finding_id in {None, finding.finding_id}
    ]
    if len(by_location) == 1:
        return by_location[0]
    if len(by_location) > 1 or candidates:
        raise _ReviewRejected("finding_association_ambiguous")
    return None


def _consume_one(
    finding: Finding,
    scan: ScanResult,
    evidence_items: tuple[TaintEvidence, ...],
    *,
    rules_file: Path | None,
    trusted_rules_directory: Path | None,
) -> ValidatedEvidence:
    evidence = _evidence_for_finding(finding, evidence_items)
    summary = build_evidence_summary(
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=rules_file,
        trusted_rules_directory=trusted_rules_directory,
    )
    return consume_evidence_summary(
        summary,
        finding,
        evidence=evidence,
        scan_result=scan,
        rules_file=rules_file,
        trusted_rules_directory=trusted_rules_directory,
    )


def _source_text(claim) -> str:
    return ", ".join(_SOURCE_LABEL[source] for source in claim.evidence_provenance) or "출처 정보 없음"


def _reason_text(claim) -> str:
    if not claim.reason_codes:
        return "추가 설명이 필요한 제한 사항입니다."
    return " ".join(_REASON_LABEL.get(code, "추가 검토가 필요합니다.") for code in claim.reason_codes)


def _render_card(
    number: int,
    finding: Finding,
    scan: ScanResult,
    evidence_items: tuple[TaintEvidence, ...],
    *,
    rules_file: Path | None,
    trusted_rules_directory: Path | None,
) -> tuple[str, bool]:
    scan_is_reviewable = scan.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}
    if scan_is_reviewable:
        try:
            validated = _consume_one(
                finding,
                scan,
                evidence_items,
                rules_file=rules_file,
                trusted_rules_directory=trusted_rules_directory,
            )
        except Exception:
            validated = None
    else:
        validated = None

    if validated is None:
        kind_label = "검증 불가"
        headline = "근거 연결을 검증할 수 없습니다."
    else:
        kind_label = _KIND_LABEL[validated.finding_kind]
        headline = {
            FindingKind.TAINT: "taint 규칙 매치 검토",
            FindingKind.PATTERN: "Semgrep 패턴 매치 검토",
            FindingKind.UNCLASSIFIED: "탐지 근거 분류 확인 필요",
        }[validated.finding_kind]

    lines = [
        f"검토 대상 #{number} (표시 순서이며 위험 순위가 아님)",
        f"요약: {headline}",
        f"Finding ID: {_safe_identifier(validated.finding_id if validated is not None else None)}",
        f"규칙 ID: {_safe_identifier(finding.rule_id)}",
        "Semgrep 심각도 분류: "
        + (
            f"{_SEVERITY_LABEL[finding.severity]} (실제 악용 가능성 판정은 아님)"
            if isinstance(finding.severity, Severity)
            else "확인 불가"
        ),
        "검증 상태: "
        + (
            _FINDING_STATUS_LABEL[finding.status]
            if isinstance(finding.status, FindingStatus)
            else "확인 불가"
        ),
        f"탐지 유형: {kind_label}",
    ]
    if _safe_relative_path(finding.file_path):
        line_number = (
            str(finding.line_number)
            if type(finding.line_number) is int and finding.line_number > 0
            else "?"
        )
        lines.append(f"Semgrep 매치 위치: {_escaped(finding.file_path)}:{line_number} (상대 경로)")
    else:
        lines.append("Semgrep 매치 위치: 안전한 상대 경로가 아니어서 숨김")

    if validated is None:
        failure_reason = (
            "scan_not_reviewable"
            if not scan_is_reviewable
            else "review_evidence_validation_failed"
        )
        failure_description = (
            "검사 실패 상태에서는 근거를 검증된 사실로 표시하지 않습니다."
            if not scan_is_reviewable
            else "근거 검증이 실패했습니다."
        )
        lines.extend(
            [
                f"근거 검증: 실패 ({failure_reason})",
                "확인된 사실: 표시할 수 없습니다.",
                f"확인되지 않은 정보: {failure_description}",
            ]
        )
        return "\n".join(lines), False

    lines.append("근거 검증: 통과 (구조적 연결만 확인; 취약점 검증을 뜻하지 않음)")
    if scan.status not in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}:
        lines.append("검증된 근거를 확인할 수 없습니다. 검사 실패 상태입니다.")
    lines.append("확인된 사실:")
    if validated.allowed_claims:
        for claim in validated.allowed_claims:
            text = _CLAIM_TEXT.get(claim.claim_type, "확인된 구조적 근거가 있습니다.")
            lines.append(f"- {text} (출처: {_source_text(claim)})")
    else:
        lines.append("- 허용된 근거 주장이 없습니다.")
    lines.append("확인되지 않았거나 이 분석에서 지원하지 않는 내용:")
    for claim in validated.restricted_claims:
        text = _CLAIM_LABEL.get(claim.claim_type, "확인 대상")
        decision = _DECISION_LABEL.get(claim.decision, "판정 불가")
        lines.append(f"- 확인 항목: {text} [{decision}] {_reason_text(claim)}")
    unique_limitations = tuple(dict.fromkeys(validated.limitations))
    already_explained = {
        reason
        for claim in validated.restricted_claims
        for reason in claim.reason_codes
    }
    remaining_limitations = tuple(
        limitation for limitation in unique_limitations if limitation not in already_explained
    )
    if remaining_limitations:
        lines.append("근거의 해석 제한:")
        for limitation in remaining_limitations:
            lines.append(f"- {_REASON_LABEL.get(limitation, '추가 검토가 필요합니다.')}")
    lines.append("분석가 검토 항목:")
    for index, (title, description) in enumerate(_TASKS[validated.finding_kind], start=1):
        lines.append(f"{index}. {title} — {description}")
    return "\n".join(lines), True


def render_review(
    scan: ScanResult,
    evidence_items: tuple[TaintEvidence, ...] = (),
    *,
    rules_file: Path | None = None,
    trusted_rules_directory: Path | None = None,
) -> str:
    """Render fixed Korean review guidance using only revalidated Gate output."""
    if not isinstance(scan, ScanResult):
        return "검토용 분석 결과\n검사 상태: 확인 불가\n검토 화면을 생성할 수 없습니다."

    status = scan.status if isinstance(scan.status, ScanStatus) else None
    status_label = _STATUS_LABEL.get(status, "확인 불가")
    complete = status is ScanStatus.COMPLETED
    counts = _severity_counts(scan)
    findings = tuple(item for item in scan.findings if isinstance(item, Finding))
    invalid_finding_count = len(scan.findings) - len(findings)
    failed = status not in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}

    lines = [
        "검토용 분석 결과",
        f"검사 상태: {status_label}",
        f"검사 완료: {'예' if complete else '아니요'}",
        "Semgrep 버전: "
        + (
            scan.semgrep_version
            if isinstance(scan.semgrep_version, str) and _VERSION.fullmatch(scan.semgrep_version)
            else "확인 불가"
        ),
        f"검토 대상: {len(scan.findings)}건 (취약점 확정 수가 아님)",
        "도구 심각도 분류별 검토 대상: "
        + ", ".join(f"{_SEVERITY_LABEL[severity]} {counts[severity]}건" for severity in Severity),
        f"검사 진단 항목: {len(scan.issues)}건",
    ]
    if failed:
        lines.append(
            "주의: 검사가 실패했습니다. 아래 자료를 정상 완료된 분석 결과로 신뢰하지 마세요."
        )
    if status is ScanStatus.PARTIAL:
        lines.append(
            "주의: 일부 경로 또는 규칙이 누락될 수 있어 전체 검사가 완료되지 않았습니다."
        )
    safe_issue_labels = []
    for issue in scan.issues:
        if not isinstance(issue, str):
            continue
        label = _ISSUE_LABEL.get(issue)
        if label and label not in safe_issue_labels:
            safe_issue_labels.append(label)
    if safe_issue_labels:
        lines.append("검사 안내: " + "; ".join(safe_issue_labels[:10]))
        if len(safe_issue_labels) > 10:
            lines.append(f"추가 검사 안내 생략: {len(safe_issue_labels) - 10}건")
    lines.extend(
        [
            "해석 제한: 각 Finding은 검토 대상이며 취약점 확정이 아닙니다.",
            "해석 제한: 탐지 0건도 대상 코드가 안전하다는 뜻은 아닙니다.",
            "해석 제한: 이 도구는 OS 수준 네트워크 격리를 제공하지 않습니다.",
        ]
    )
    rendered_cards: list[str] = []
    consumer_failures = 0
    display_limit = min(len(findings), MAX_REVIEW_FINDINGS)
    for index, finding in enumerate(findings[:display_limit], start=1):
        card, valid = _render_card(
            index,
            finding,
            scan,
            evidence_items if isinstance(evidence_items, tuple) else (),
            rules_file=rules_file,
            trusted_rules_directory=trusted_rules_directory,
        )
        if not valid:
            consumer_failures += 1
        candidate = "\n\n".join([*lines, *rendered_cards, card])
        if len(candidate.encode("utf-8")) > MAX_REVIEW_OUTPUT_BYTES:
            break
        rendered_cards.append(card)

    shown = len(rendered_cards)
    omitted = len(findings) - shown
    lines.extend(rendered_cards)
    if consumer_failures:
        lines.append(
            f"근거를 확인 사실로 표시하지 않은 Finding: {consumer_failures}건. "
            "검사 상태 또는 근거 검증을 확인하세요."
        )
    if invalid_finding_count:
        lines.append(f"잘못된 Finding 형식으로 표시하지 않은 항목: {invalid_finding_count}건")
    if omitted:
        lines.append(f"출력 제한으로 표시하지 않은 검토 대상: {omitted}건")
        lines.append(
            "생략된 항목의 개별 검증 상태는 확인할 수 없으며 안전하다고 판단할 수 없습니다."
        )
    output = "\n\n".join(lines)
    if len(output.encode("utf-8")) > MAX_REVIEW_OUTPUT_BYTES:
        return (
            "검토용 분석 결과\n"
            f"검토 대상: {len(scan.findings)}건\n"
            "표시된 상세: 0건\n"
            f"생략된 상세: {len(scan.findings)}건 (전체 보고서 바이트 제한)\n"
            "요약 제한: 생략된 항목의 개별 검증 상태는 이 화면에서 확인할 수 없습니다.\n"
            "기존 text 또는 JSON 형식으로 전체 결과를 확인하세요."
        )
    return output
