"""Render a safe Review View from Phase 6J synthetic code using real Semgrep."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.taint_evidence import EvidenceState, TraceStatus


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
EVAL_RULES = RULES / "experimental" / "javascript-eval-taint.yml"
FIXTURES = ROOT / "tests" / "fixtures" / "review_semantics_phase6j"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="phase6j-review-") as temporary:
        target = Path(temporary)
        for relative in (Path("framework/route.js"), Path("generic/job.js")):
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(FIXTURES / relative, destination)

        adapter = SemgrepAdapter(RULES)
        scanned = adapter._scan_with_evidence(target, EVAL_RULES)
        if scanned.result.status is not ScanStatus.COMPLETED or len(scanned.result.findings) != 4:
            print("Phase 6J 검수 자료 생성 실패: 기대한 합성 검사 상태와 Finding 수가 다릅니다.")
            return 1
        evidence_by_finding = {item.finding_id: item for item in scanned.taint_evidence}
        if any(finding.status is not FindingStatus.UNVERIFIED for finding in scanned.result.findings):
            print("Phase 6J 검수 자료 생성 실패: Finding 검증 상태가 기대와 다릅니다.")
            return 1
        if len(evidence_by_finding) != 4 or any(
            evidence_by_finding.get(finding.finding_id) is None
            or evidence_by_finding[finding.finding_id].source_location is not None
            or evidence_by_finding[finding.finding_id].source_location_status is not EvidenceState.UNKNOWN
            or evidence_by_finding[finding.finding_id].sink_location is not None
            or evidence_by_finding[finding.finding_id].sink_location_status is not EvidenceState.UNKNOWN
            or evidence_by_finding[finding.finding_id].flow_trace_status is not TraceStatus.ABSENT
            for finding in scanned.result.findings
        ):
            print("Phase 6J 검수 자료 생성 실패: Source/Sink/trace 제한이 기대와 다릅니다.")
            return 1
        output = render_review(
            scanned.result,
            scanned.taint_evidence,
            rules_file=EVAL_RULES,
            trusted_rules_directory=RULES,
        )
        if any(
            forbidden in output
            for forbidden in (
                "request.body.code",
                "job.body.code",
                "eval(expression)",
                "취약점이 확인되었습니다",
            )
        ):
            print("Phase 6J 검수 자료 생성 실패: 원본 코드 또는 금지된 확정 표현이 포함됐습니다.")
            return 1
        if output.count("근거 검증: 통과 (구조적 연결만 확인; 취약점 검증을 뜻하지 않음)") != 4:
            print("Phase 6J 검수 자료 생성 실패: 구조적 근거 검증 결과가 기대와 다릅니다.")
            return 1
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
