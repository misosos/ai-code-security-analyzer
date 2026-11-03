import type { ApiFinding, ClaimType, FindingKind, ScanResponse, Severity } from '../../api/types';
import { getFindingReviewGuidance } from './reviewGuidance';

export type TriageRecommendation = 'evidence_review' | 'priority_code_review' | 'code_review';

export interface FindingTriage {
  findingId: string;
  ruleId: string;
  filePath: string | null;
  lineNumber: number | null;
  severity: Severity;
  findingKind: FindingKind;
  evidenceValidationStatus: ApiFinding['evidence_validation_status'];
  verificationStatus: ApiFinding['verification_status'];
  ruleTitle: string;
  ruleFinding: string;
  recommendation: TriageRecommendation;
  recommendationLabel: string;
  explanation: string;
  basis: readonly string[];
  structuralEvidence: readonly string[];
  supportedClaims: readonly ClaimType[];
  notVerified: readonly string[];
  tasks: readonly string[];
  actions: readonly string[];
  scopeNotice: string | null;
}

export interface ScanTriage {
  scopeNotice: string | null;
  emptyResultNotice: string | null;
  findings: FindingTriage[];
}

const severityLabels: Record<Severity, string> = {
  critical: '매우 높음', high: '높음', medium: '중간', low: '낮음', info: '정보',
};

const statusLabels: Record<ScanResponse['scan_status'], string> = {
  completed: '정상 완료', partial: '부분 검사', execution_failed: '실행 실패', not_installed: 'Semgrep 미설치',
  invalid_json: '결과 형식 오류', timed_out: '시간 초과', output_limit_exceeded: '출력 제한 초과',
};

function scanScopeNotice(scan: ScanResponse): string | null {
  const limits: string[] = [];
  if (!scan.completed) {
    limits.push(`${statusLabels[scan.scan_status]} 결과입니다. 현재 응답에 표시된 Finding만 검토 대상으로 안내하며 전체 검사 우선순위를 뜻하지 않습니다.`);
  }
  if (scan.omitted_finding_count > 0) {
    limits.push(`${scan.omitted_finding_count}개 Finding이 생략되어 현재 표시된 항목만 안내합니다. 생략된 항목의 우선순위는 계산하지 않았습니다.`);
  }
  return limits.length ? limits.join(' ') : null;
}

function recommendationFor(finding: ApiFinding): TriageRecommendation {
  if (finding.evidence_validation_status !== 'validated') return 'evidence_review';
  return finding.severity === 'critical' || finding.severity === 'high' ? 'priority_code_review' : 'code_review';
}

function recommendationText(recommendation: TriageRecommendation, finding: ApiFinding): { label: string; explanation: string } {
  if (recommendation === 'evidence_review') {
    return {
      label: '근거 연결 확인 필요',
      explanation: `근거 연결이 ${finding.evidence_validation_status} 상태여서 근거 연결 확인이 먼저 필요합니다. 도구 심각도 ${severityLabels[finding.severity]}은 그대로 표시되며, 근거 부족이 위험도가 낮다는 뜻은 아닙니다.`,
    };
  }
  if (recommendation === 'priority_code_review') {
    return {
      label: '우선 코드 검토 권장',
      explanation: `도구가 ${severityLabels[finding.severity]} 심각도로 분류한 패턴이 보고됐고 근거 연결이 구조적으로 검증됐습니다. 실제 취약점 여부와 악용 가능성은 추가 확인이 필요합니다.`,
    };
  }
  return {
    label: '코드 검토 권장',
    explanation: `도구가 ${severityLabels[finding.severity]} 심각도로 분류한 패턴이 보고됐고 근거 연결이 구조적으로 검증됐습니다. 심각도만으로 취약점 유무나 안전성을 판단할 수 없습니다.`,
  };
}

function makeFindingTriage(finding: ApiFinding, scopeNotice: string | null): FindingTriage {
  const guidance = getFindingReviewGuidance(finding.rule_id, finding.finding_kind);
  const recommendation = recommendationFor(finding);
  const recommendationCopy = recommendationText(recommendation, finding);
  const kindLabel = finding.finding_kind === 'taint' ? 'Taint' : finding.finding_kind === 'pattern' ? '일반 패턴' : '분류되지 않음';
  return {
    findingId: finding.finding_id,
    ruleId: finding.rule_id,
    filePath: finding.file_path,
    lineNumber: finding.line_number,
    severity: finding.severity,
    findingKind: finding.finding_kind,
    evidenceValidationStatus: finding.evidence_validation_status,
    verificationStatus: finding.verification_status,
    ruleTitle: guidance.title,
    ruleFinding: guidance.finding,
    recommendation,
    recommendationLabel: recommendationCopy.label,
    explanation: recommendationCopy.explanation,
    basis: [
      `Semgrep 도구 심각도: ${severityLabels[finding.severity]} (${finding.severity})`,
      `근거 연결 검증: ${finding.evidence_validation_status}`,
      `도구가 보고한 분석 유형: ${kindLabel}`,
    ],
    structuralEvidence: finding.evidence_validation_status === 'validated'
      ? ['API 응답에서 Finding과 보고된 근거의 구조적 연결이 validated 상태입니다. 이는 취약점 확정이나 실제 악용 가능성 확인이 아닙니다.']
      : [],
    supportedClaims: finding.evidence_validation_status === 'validated' ? [...finding.supported_claims] : [],
    notVerified: [
      '실제 취약점 여부와 악용 가능성',
      '외부 입력이 해당 코드에 도달하거나 값을 제어하는지',
      '실행 경로, 운영 환경 및 방어 조건의 실제 효과',
    ],
    tasks: guidance.tasks,
    actions: guidance.actions,
    scopeNotice,
  };
}

/** Create deterministic analyst work suggestions from the validated API response only. */
export function createScanTriage(scan: ScanResponse): ScanTriage {
  const scopeNotice = scanScopeNotice(scan);
  return {
    scopeNotice,
    emptyResultNotice: scan.findings.length === 0
      ? '현재 응답에 표시된 Finding이 없습니다. 탐지 0건은 프로젝트 안전성이나 전체 코드 검사를 증명하지 않습니다.'
      : null,
    findings: scan.findings.map((finding) => makeFindingTriage(finding, scopeNotice)),
  };
}
