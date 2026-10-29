import type { ApiFinding, ClaimType, ScanResponse } from '../../api/types';

export interface ScanContext {
  targetId: string;
  targetLabel: string;
  ruleProfileId: string;
  ruleProfileLabel: string;
  experimental: boolean;
  scanStatus: ScanResponse['scan_status'];
  receivedAt: string;
}

export const MAX_REVIEW_MARKDOWN_BYTES = 512 * 1024;
export const REVIEW_MARKDOWN_FILENAME = 'ai-code-security-ui-review-summary.md';

const claimLabels: Record<ClaimType, string> = {
  match_reported: 'Semgrep 규칙 매치 보고', taint_rule_match_reported: '신뢰된 taint 규칙 매치 보고',
  source_pattern_declared: '규칙의 Source 패턴 선언', sink_pattern_declared: '규칙의 Sink 패턴 선언',
  match_location_observed: 'Semgrep 매치 위치 관찰', source_location_identified: '실제 Source 위치 식별',
  sink_argument_location_identified: 'Sink 인자 위치 식별', flow_trace_available: '구조화된 흐름 trace 제공',
  sanitizer_match_observed: 'Sanitizer 매치 관찰', sanitizer_effectiveness_verified: 'Sanitizer 효과 검증',
  vulnerability_confirmed: '취약점 확정',
};
const decisionLabels = { insufficient_evidence: '근거 부족', unavailable: '현재 자료에서 확인 불가', ambiguous: '근거 연결 모호', unsupported_claim: '현재 정책에서 지원하지 않는 주장' } as const;
const reasonLabels: Record<string, string> = {
  source_location_unknown: '실제 Source 위치 정보가 제공되지 않았습니다.', source_location_unavailable: '실제 Source 위치를 확인할 수 없습니다.',
  sink_argument_location_unknown: 'Sink 인자 위치 정보가 제공되지 않았습니다.', sink_argument_location_unavailable: 'Sink 인자 위치를 확인할 수 없습니다.',
  match_location_not_sink_argument: '매치 위치는 Sink 인자 위치로 확인되지 않았습니다.', flow_trace_absent: '구조화된 데이터 흐름 trace가 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다.',
  flow_trace_empty: 'Trace가 비어 있습니다. 흐름이 없다는 뜻은 아닙니다.', flow_trace_unsupported: 'Trace 구조가 지원되지 않습니다.',
  source_sink_path_unproven: '전체 Source→Sink 경로는 입증되지 않았습니다.', sanitizer_match_unknown: 'Sanitizer 적용 여부가 확인되지 않았습니다.',
  sanitizer_effectiveness_not_verified: '정제 함수의 실제 보안 효과는 검증되지 않았습니다.', independent_confirmation_required: '취약점 확정에는 별도의 확인이 필요합니다.',
  taint_match_not_vulnerability_confirmation: 'Taint 규칙 매치는 취약점 확정이 아닙니다.', rule_declaration_not_observed_code: '규칙 선언은 실제 코드 위치의 관찰이 아닙니다.',
  rule_file_at_scan_time_unproven: '검사 시점에 사용된 규칙 파일의 원자적 동일성은 증명되지 않았습니다.',
  scan_partial: '검사가 일부만 완료됐습니다.', scan_not_complete: '전체 검사가 완료되지 않았습니다.', scan_failed: '검사가 실패했습니다.',
  static_evidence_cannot_support_claim: '현재 정적 근거로는 이 주장을 지원할 수 없습니다.',
};
const statusLabels: Record<ScanResponse['scan_status'], string> = {
  completed: '정상 완료', partial: '부분 검사', execution_failed: '실행 실패', not_installed: 'Semgrep 미설치',
  invalid_json: '결과 형식 오류', timed_out: '시간 초과', output_limit_exceeded: '출력 제한 초과',
};
const kindLabels = { taint: 'Taint', pattern: '일반 패턴', unclassified: '분류되지 않음' } as const;
const taskText = {
  taint: ['실제 입력 출처를 코드에서 확인하세요.', '위험 함수에 전달되는 인자와 변수 관계를 확인하세요.', '입력 검증과 정제 로직을 확인하세요.', '함수 경계 밖의 전달 흐름을 직접 검토하세요.', '런타임 도달 조건을 확인하세요.'],
  pattern: ['탐지된 패턴과 표시 위치를 확인하세요.', '입력값과 데이터 출처를 확인하세요.', '주변의 방어 조건을 검토하세요.'],
  unclassified: ['규칙과 근거 연결을 확인하세요.', '매치 위치와 규칙 ID를 확인하세요.', '분류에 필요한 근거가 누락됐는지 검토하세요.'],
} as const;

// Encode Markdown/HTML delimiters and invisible formatting characters as entities so
// user-controlled identifiers cannot create headings, links, tags, or new blocks.
export function escapeMarkdownText(value: string): string {
  let output = '';
  for (const char of value) {
    const code = char.codePointAt(0)!;
    if (/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(char) || /[\\`*_{}\[\]()#+!|>~&<>]/u.test(char)) {
      output += `&#x${code.toString(16).toUpperCase()};`;
    } else output += char;
  }
  return output;
}

function label(value: string, labels: Record<string, string>): string { return escapeMarkdownText(labels[value] ?? '확인 불가'); }
function reason(value: string): string { return escapeMarkdownText(reasonLabels[value] ?? '추가 검토가 필요합니다.'); }
function findingMarkdown(finding: ApiFinding, index: number): string {
  const lines = [
    `### 검토 대상 ${index + 1}`,
    `- Finding ID: ${escapeMarkdownText(finding.finding_id)}`,
    `- Rule ID: ${escapeMarkdownText(finding.rule_id)}`,
    `- 심각도: ${escapeMarkdownText(finding.severity)} · 검증 상태: 미검증`,
    `- 탐지 유형: ${kindLabels[finding.finding_kind]}`,
    `- 위치: ${finding.file_path ? escapeMarkdownText(finding.file_path) : '확인 불가'}${finding.line_number ? `:${finding.line_number}` : ''}`,
    `- 근거 검증: ${escapeMarkdownText(finding.evidence_validation_status)}`,
    '', '확인된 구조적 근거:',
  ];
  if (finding.evidence_validation_status !== 'validated') lines.push('- 근거 검증에 실패했거나 사용할 수 없어 지원된 주장을 표시하지 않습니다.');
  else if (finding.supported_claims.length) for (const claim of finding.supported_claims) lines.push(`- ${label(claim, claimLabels)}`);
  else lines.push('- 지원된 주장이 없습니다.');
  lines.push('', '제한된 주장:');
  if (finding.restricted_claims.length) {
    for (const claim of finding.restricted_claims) {
      lines.push(`- ${label(claim.claim_type, claimLabels)} (${escapeMarkdownText(claim.claim_type)}) — ${label(claim.decision, decisionLabels)} (${escapeMarkdownText(claim.decision)})`);
      for (const code of claim.reason_codes) lines.push(`  - ${reason(code)} (${escapeMarkdownText(code)})`);
    }
  } else lines.push('- 제한된 주장이 없습니다.');
  lines.push('', '분석가 추가 검토 제안 (완료된 검증이 아님):');
  for (const task of taskText[finding.finding_kind]) lines.push(`- ${task}`);
  return lines.join('\n');
}

export function createReviewMarkdown(context: ScanContext, scan: ScanResponse): string {
  if (context.scanStatus !== scan.scan_status) throw new Error('scan_context_mismatch');
  const sections = [
    '# AI Code Security Analyzer — UI Analyst Review Summary',
    '', '> 로컬 정적 분석 결과입니다. 취약점 확정 문서가 아니며, UI 응답에 표시된 Finding만 포함합니다. 별도의 코드 및 런타임 검토가 필요합니다.',
    '', '## 검사 문맥',
    `- 검사 대상: ${escapeMarkdownText(context.targetLabel)} (${escapeMarkdownText(context.targetId)})`,
    `- 규칙 프로필: ${escapeMarkdownText(context.ruleProfileLabel)} (${escapeMarkdownText(context.ruleProfileId)})${context.experimental ? ' · Experimental' : ' · Baseline'}`,
    `- 결과 수신 시각 (브라우저 로컬 기록): ${escapeMarkdownText(context.receivedAt)}`,
    `- Semgrep 버전: ${scan.semgrep_version ? escapeMarkdownText(scan.semgrep_version) : '확인 불가'}`,
    `- 검사 상태: ${statusLabels[scan.scan_status]} · completed=${scan.completed ? 'true' : 'false'}`,
    '', '## 검사 요약',
    `- 전체 Finding: ${scan.finding_count}`,
    `- 이 문서에 포함된 Finding: ${scan.findings.length}`,
    `- 생략된 Finding: ${scan.omitted_finding_count}`,
    `- 심각도 집계: ${Object.entries(scan.severity_counts).map(([severity, count]) => `${severity} ${count}`).join(', ')}`,
  ];
  if (scan.omitted_finding_count > 0) sections.push('', `> 경고: 이 문서는 전체 Finding 목록을 포함하지 않습니다. 생략된 ${scan.omitted_finding_count}개 항목의 개별 검증 상태는 확인할 수 없습니다.`);
  if (scan.issues.length) sections.push('', '### 검사 안내 코드', ...scan.issues.map((item) => `- ${escapeMarkdownText(item)}`));
  if (scan.limitations.length) sections.push('', '### 검사 제한 코드', ...scan.limitations.map((item) => `- ${escapeMarkdownText(item)}`));
  sections.push('', '## Finding 검토');
  if (!scan.findings.length) sections.push('응답에 표시된 Finding이 없습니다. 탐지 0건은 코드가 안전하다는 증명이 아닙니다.');
  else scan.findings.forEach((finding, index) => sections.push(findingMarkdown(finding, index)));
  sections.push('', '## 일반적인 분석 한계',
    '- Finding 상태는 미검증이며, 도구 심각도는 실제 악용 가능성 확인이 아닙니다.',
    '- Source/Sink 위치 또는 trace가 제공되지 않았다는 사실은 해당 데이터 흐름이 없다는 뜻이 아닙니다.',
    '- 규칙 선언과 실제 코드의 보안적 의미는 구분됩니다.',
    '- 검사 완료는 코드 안전성 증명이 아닙니다.',
    '- 이 UI 요약은 CLI의 정식 `review-md` 보고서를 대체하지 않습니다.',
    '- 상대 경로와 규칙 식별자는 저장소 구조를 드러낼 수 있습니다. 외부 공유 전 직접 검토하세요.');
  const markdown = `${sections.join('\n')}\n`;
  const byteLength = new TextEncoder().encode(markdown).byteLength;
  if (byteLength > MAX_REVIEW_MARKDOWN_BYTES) throw new Error('export_size_limit_exceeded');
  return markdown;
}

export function downloadReviewMarkdown(markdown: string): void {
  if (new TextEncoder().encode(markdown).byteLength > MAX_REVIEW_MARKDOWN_BYTES) throw new Error('export_size_limit_exceeded');
  const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = REVIEW_MARKDOWN_FILENAME;
  anchor.hidden = true;
  document.body.append(anchor);
  try { anchor.click(); }
  finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
