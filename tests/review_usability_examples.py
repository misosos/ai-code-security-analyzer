"""Render reproducible synthetic screens for a future analyst study."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import build_taint_evidence


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
PATTERN_RULE = RULES / "security-baseline.yml"
CANARY = "SYNTHETIC_REVIEW_DISPLAY_CANARY"
CASES = ("taint", "pattern", "partial", "failed", "zero")
_FINDING_HEADING = re.compile(r"^검토 대상 #\d+ \(표시 순서이며 위험 순위가 아님\)$")
_REVIEW_COUNT = re.compile(r"^검토 대상: (\d+)건")
_OMITTED_COUNT = re.compile(r"^(?:출력 제한으로 표시하지 않은 검토 대상|생략된 상세): (\d+)건")
_REPEATED_GUIDANCE = (
    "Semgrep이 해당 규칙 매치를 보고했습니다.",
    "Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다.",
    "이 결과만으로 취약점이 확인된 것은 아닙니다.",
    "실제 Source 위치 정보가 제공되지 않았습니다.",
    "구조화된 데이터 흐름 trace가 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다.",
)


def render_case(name: str) -> str:
    """Return one complete review screen produced from fixed synthetic metadata."""
    if name not in CASES:
        raise ValueError("unsupported synthetic review case")
    if name == "zero":
        return render_review(ScanResult(ScanStatus.COMPLETED, (), (), 0, "1.182.1"), ())

    rule_id = (
        "experimental.javascript-eval-taint"
        if name in {"taint", "partial", "failed"}
        else "baseline.javascript-dynamic-eval"
    )
    rule_file = TAINT_RULE if rule_id.startswith("experimental.") else PATTERN_RULE
    with TemporaryDirectory(prefix="synthetic-review-display-") as temporary:
        target = Path(temporary)
        raw = {
            "version": "1.182.1",
            "engine_requested": "OSS",
            "results": [
                {
                    "check_id": rule_id,
                    "path": "src/synthetic-review.ts",
                    "start": {"line": 12, "col": 3},
                    "end": {"line": 12, "col": 9},
                    "extra": {
                        "message": f"Synthetic tool message {CANARY}",
                        "severity": "ERROR",
                        "engine_kind": "OSS",
                        "lines": f"eval('{CANARY}')",
                    },
                }
            ],
            "errors": [],
        }
        parsed = _parse_semgrep_json_internal(json.dumps(raw).encode("utf-8"), target)
        finding = parsed.parsed.findings[0]
        status = ScanStatus.PARTIAL if name == "partial" else ScanStatus.COMPLETED
        issues = ("semgrep_skipped_paths",) if name == "partial" else ()
        scan = ScanResult(status, (finding,), issues, 0, "1.182.1")
        evidence = (
            build_taint_evidence(
                parsed.document,
                parsed.result_findings,
                target,
                rules_file=rule_file,
                trusted_rules_directory=RULES,
            )
            if rule_file is TAINT_RULE
            else ()
        )
        if name == "failed":
            scan = replace(scan, status=ScanStatus.TIMED_OUT, issues=("semgrep_timeout",), exit_code=None)
        return render_review(
            scan,
            evidence,
            rules_file=rule_file,
            trusted_rules_directory=RULES,
        )


def measure_case(name: str) -> dict[str, object]:
    """Measure safe, display-level metrics from a reproducible synthetic screen."""
    output = render_case(name)
    lines = output.splitlines()
    findings_match = next(
        (match for line in lines if (match := _REVIEW_COUNT.match(line)) is not None),
        None,
    )
    finding_count = int(findings_match.group(1)) if findings_match else None
    cards = [index for index, line in enumerate(lines) if _FINDING_HEADING.match(line)]
    card_line_counts = [
        (cards[index + 1] if index + 1 < len(cards) else len(lines)) - start
        for index, start in enumerate(cards)
    ]

    def count_section_items(heading: str, item_prefix: str) -> int:
        try:
            start = next(index for index, line in enumerate(lines) if line == heading)
        except StopIteration:
            return 0
        count = 0
        for line in lines[start + 1 :]:
            if line and not line.startswith(item_prefix) and not line.startswith("  "):
                break
            if line.startswith(item_prefix):
                count += 1
        return count

    phrases = {
        phrase: output.count(phrase)
        for phrase in _REPEATED_GUIDANCE
        if output.count(phrase) > 1
    }
    omitted_match = next(
        (match for line in lines if (match := _OMITTED_COUNT.match(line)) is not None),
        None,
    )
    omitted_count = int(omitted_match.group(1)) if omitted_match else 0

    def first_line_containing(needle: str) -> int | None:
        return next((index for index, line in enumerate(lines, start=1) if needle in line), None)

    return {
        "case": name,
        "line_count": len(lines),
        "utf8_bytes": len(output.encode("utf-8")),
        "finding_count": finding_count,
        "displayed_finding_count": len(cards),
        "finding_card_line_counts": card_line_counts,
        "displayed_supported_claim_count": count_section_items("확인된 사실:", "- "),
        "displayed_restricted_claim_count": count_section_items(
            "확인되지 않았거나 이 분석에서 지원하지 않는 내용:", "- 확인 항목:"
        ),
        "analyst_review_item_count": sum(bool(re.match(r"^\d+\. ", line)) for line in lines),
        "repeated_fixed_phrases": phrases,
        "first_scan_status_line": first_line_containing("검사 상태:"),
        "first_core_limitation_line": first_line_containing("해석 제한:")
        or first_line_containing("주의:"),
        "first_unavailable_information_line": first_line_containing("확인되지 않았거나"),
        "omission_occurred": omitted_count > 0,
        "omitted_finding_count": omitted_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=(*CASES, "all"), default="all")
    parser.add_argument("--metrics", action="store_true", help="emit safe display-level metrics as JSON")
    args = parser.parse_args()
    names = CASES if args.case == "all" else (args.case,)
    if args.metrics:
        print(json.dumps([measure_case(name) for name in names], ensure_ascii=False, indent=2))
        return 0
    for name in names:
        print(f"===== SYNTHETIC CASE: {name} =====")
        print(render_case(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
