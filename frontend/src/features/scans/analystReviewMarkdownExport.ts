import { parseScan, type ApiFinding, type ClaimType, type ScanResponse, type ScanStatus } from '../../api/types';
import { MAX_ANALYST_NOTE_BYTES, type AnalystReviewState, type AnalystReviewStatus } from './analystReview';
import { escapeMarkdownText, MAX_REVIEW_MARKDOWN_BYTES, type ScanContext } from './markdownExport';

export const ANALYST_REVIEW_MARKDOWN_FILENAME = 'ai-code-security-analyst-review.md';
export const MAX_ANALYST_REVIEW_MARKDOWN_BYTES = MAX_REVIEW_MARKDOWN_BYTES;

const statuses: Record<AnalystReviewStatus, string> = { pending: '검토 대기', needs_followup: '추가 확인 필요', reviewed: '검토 완료' };
const scanStatuses: Record<ScanStatus, string> = {
  completed: '정상 완료', partial: '부분 검사', execution_failed: '실행 실패', not_installed: 'Semgrep 미설치',
  invalid_json: '결과 형식 오류', timed_out: '시간 초과', output_limit_exceeded: '출력 제한 초과',
};
const kinds = { taint: 'Taint', pattern: '일반 패턴', unclassified: '분류되지 않음' } as const;
const claimLabels: Record<ClaimType, string> = {
  match_reported: '규칙 매치 보고', taint_rule_match_reported: 'Taint 규칙 매치 보고', source_pattern_declared: '규칙의 Source 패턴 선언',
  sink_pattern_declared: '규칙의 Sink 패턴 선언', match_location_observed: '매치 위치 관찰', source_location_identified: '실제 Source 위치 식별',
  sink_argument_location_identified: 'Sink 인자 위치 식별', flow_trace_available: '구조화된 흐름 Trace 제공', sanitizer_match_observed: 'Sanitizer 매치 관찰',
  sanitizer_effectiveness_verified: 'Sanitizer 효과 검증', vulnerability_confirmed: '취약점 확정',
};

function escaped(value: string): string { return escapeMarkdownText(value); }
function safePath(path: string | null): string {
  if (path === null) return '파일 위치 확인 불가';
  if (!path || path.startsWith('/') || path.startsWith('\\\\') || /^[A-Za-z]:/.test(path) || path.includes('\\')
    || /[\p{C}]/u.test(path) || path.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error('scan_response_invalid');
  }
  return escaped(path);
}

function validateContext(context: ScanContext, scan: ScanResponse): void {
  const absolutePathLabel = (value: unknown): boolean => typeof value === 'string'
    && (value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('\\\\') || value.startsWith('~/'));
  if (!context || typeof context !== 'object'
    || typeof context.targetId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(context.targetId)
    || typeof context.ruleProfileId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(context.ruleProfileId)
    || typeof context.targetLabel !== 'string' || context.targetLabel.length > 128 || /[\p{C}]/u.test(context.targetLabel) || absolutePathLabel(context.targetLabel)
    || typeof context.ruleProfileLabel !== 'string' || context.ruleProfileLabel.length > 128 || /[\p{C}]/u.test(context.ruleProfileLabel) || absolutePathLabel(context.ruleProfileLabel)
    || typeof context.experimental !== 'boolean'
    || typeof context.receivedAt !== 'string' || context.receivedAt.length > 64 || !Number.isFinite(Date.parse(context.receivedAt))) {
    throw new Error('scan_context_invalid');
  }
  if (context.scanStatus !== scan.scan_status) throw new Error('scan_context_mismatch');
}

function validateReviewState(state: AnalystReviewState, findings: readonly ApiFinding[]): Map<string, { status: AnalystReviewStatus; note: string }> {
  if (!(state instanceof Map)) throw new Error('review_state_invalid');
  const currentIds = new Set(findings.map((item) => item.finding_id));
  const copy = new Map<string, { status: AnalystReviewStatus; note: string }>();
  for (const [findingId, raw] of state.entries()) {
    if (typeof findingId !== 'string' || !currentIds.has(findingId) || !raw || typeof raw !== 'object'
      || !['pending', 'needs_followup', 'reviewed'].includes(raw.status) || typeof raw.note !== 'string'
      || new TextEncoder().encode(raw.note).byteLength > MAX_ANALYST_NOTE_BYTES) throw new Error('review_state_invalid');
    copy.set(findingId, { status: raw.status, note: raw.note });
  }
  return copy;
}

function findingRows(finding: ApiFinding, state: { status: AnalystReviewStatus; note: string }, includeNotes: boolean): string[] {
  const location = `${safePath(finding.file_path)}${finding.line_number === null ? '' : `:${finding.line_number}`}`;
  const lines = [
    `### ${escaped(finding.rule_id)}`,
    `- Finding ID: ${escaped(finding.finding_id)}`,
    `- 규칙 ID: ${escaped(finding.rule_id)}`,
    `- 도구 보고 심각도: ${escaped(finding.severity)}`,
    `- 탐지 유형: ${kinds[finding.finding_kind]}`,
    `- 상대 위치: ${location}`,
    `- 취약점 검증 상태: ${escaped(finding.verification_status)}`,
    `- 근거 연결 검증 상태: ${escaped(finding.evidence_validation_status)}`,
    `- 분석가 수동 검토 상태: ${statuses[state.status]}`,
    `- 검증 오류 코드: ${finding.validation_error_code ? escaped(finding.validation_error_code) : '없음'}`,
    `- 지원된 주장 코드: ${finding.supported_claims.length ? finding.supported_claims.map((claim) => `${escaped(claimLabels[claim])} (${escaped(claim)})`).join(', ') : '없음'}`,
    `- 제한된 주장: ${finding.restricted_claims.length ? finding.restricted_claims.map((item) => `${escaped(claimLabels[item.claim_type])} (${escaped(item.claim_type)}): ${escaped(item.decision)}${item.reason_codes.length ? ` [${item.reason_codes.map(escaped).join(', ')}]` : ''}`).join('; ') : '없음'}`,
  ];
  if (includeNotes && state.note.length > 0) lines.push(`- 분석가 메모: ${escaped(state.note)}`);
  return lines;
}

/** 검증된 현재 검사 한 건과 해당 Finding에 연결된 분석가 기록만 생성한다. */
export function createAnalystReviewMarkdown(context: ScanContext, input: ScanResponse, state: AnalystReviewState, includeNotes: boolean): string {
  let scan: ScanResponse;
  try { scan = parseScan(input); } catch { throw new Error('scan_response_invalid'); }
  validateContext(context, scan);
  if (typeof includeNotes !== 'boolean') throw new Error('review_export_option_invalid');
  const reviews = validateReviewState(state, scan.findings);
  const counts: Record<AnalystReviewStatus, number> = { pending: 0, needs_followup: 0, reviewed: 0 };
  const sorted = [...scan.findings].sort((left, right) => left.finding_id < right.finding_id ? -1 : left.finding_id > right.finding_id ? 1 : 0);
  for (const finding of sorted) counts[reviews.get(finding.finding_id)?.status ?? 'pending'] += 1;
  const sections = [
    '# AI Code Security Analyzer — 분석가 검토 기록',
    '',
    '> 이 문서는 정적 분석 결과와 분석가의 수동 작업 기록을 함께 정리합니다. 분석가 작업 상태는 취약점 판정이 아닙니다. 검토 완료는 수정 완료나 취약점 해결을 의미하지 않습니다.',
    '', '## 검사 문맥',
    `- 검사 대상: ${escaped(context.targetLabel)} (${escaped(context.targetId)})`,
    `- 규칙 프로필: ${escaped(context.ruleProfileLabel)} (${escaped(context.ruleProfileId)}) · ${context.experimental ? 'Experimental' : 'Baseline'}`,
    `- Semgrep 버전: ${scan.semgrep_version ? escaped(scan.semgrep_version) : '확인 불가'}`,
    `- 검사 상태: ${scanStatuses[scan.scan_status]}`,
    `- 브라우저 결과 수신 시각: ${escaped(new Date(context.receivedAt).toISOString())}`,
    '- 수신 시각은 브라우저가 응답을 받은 시각이며 실제 검사 실행 시각이나 소스 코드 스냅샷 시각이 아닙니다.',
    `- 전체 Finding: ${scan.finding_count}`,
    `- 표시된 Finding: ${scan.displayed_finding_count}`,
    `- 생략된 Finding: ${scan.omitted_finding_count}`,
    '', '## 분석가 검토 요약',
    `- 검토 대기: ${counts.pending}`,
    `- 추가 확인 필요: ${counts.needs_followup}`,
    `- 검토 완료: ${counts.reviewed}`,
    `- 현재 응답에 포함된 검토 대상: ${scan.findings.length}`,
  ];
  if (scan.omitted_finding_count > 0) sections.push('', `> 범위 제한: 생략된 ${scan.omitted_finding_count}개 Finding은 이 보고서와 검토 현황에 포함되지 않습니다.`);
  if (scan.scan_status === 'partial') sections.push('', '> 검사 범위 경고: 부분 검사 응답입니다. 완료되지 않은 범위가 있을 수 있으며 전체 검사 결과로 해석하면 안 됩니다.');
  else if (!scan.completed) sections.push('', '> 검사 상태 경고: 검사가 정상 완료되지 않았습니다. 아래에는 API 응답에 포함된 항목만 기록하며 완전한 결과를 뜻하지 않습니다.');
  sections.push('', '- 검토 상태 수치는 코드 안전성 점수나 취약점 해결률이 아닙니다.', '', '## Finding별 기록', '');
  if (sorted.length === 0) sections.push('현재 API 응답에 포함된 Finding이 없습니다. 탐지 0건은 프로젝트 안전성의 증명이 아닙니다.');
  sorted.forEach((finding, index) => {
    if (index > 0) sections.push('');
    sections.push(...findingRows(finding, reviews.get(finding.finding_id) ?? { status: 'pending', note: '' }, includeNotes));
  });
  sections.push('', '## 해석 범위와 한계',
    '- Finding은 도구가 보고한 검토 후보이며 실제 취약점 확정이나 악용 가능성 확인을 뜻하지 않습니다.',
    '- `Validated Evidence`는 근거 연결의 구조적 검증 상태이며 실제 취약점 검증을 뜻하지 않습니다.',
    '- 분석가 검토 상태는 수동 업무 진행 표시이며 API의 검증 상태, 심각도 또는 근거 주장을 변경하지 않습니다.',
    '- 상대 경로와 규칙 식별자는 프로젝트 정보를 드러낼 수 있습니다. 외부 공유 전에 확인하세요.',
    '- 이 문서는 CLI의 정식 보안 검토 보고서를 대체하지 않습니다.');
  if (includeNotes) sections.push('', '> 메모 포함 안내: 분석가 메모에는 내부 코드 정보나 민감정보가 포함될 수 있습니다. 다운로드한 파일은 브라우저 메모리와 달리 디스크에 남으므로 외부 공유 전에 확인하세요.');
  const markdown = `${sections.join('\n')}\n`;
  if (new TextEncoder().encode(markdown).byteLength > MAX_ANALYST_REVIEW_MARKDOWN_BYTES) throw new Error('analyst_review_export_size_limit_exceeded');
  return markdown;
}

export function downloadAnalystReviewMarkdown(markdown: string): void {
  if (new TextEncoder().encode(markdown).byteLength > MAX_ANALYST_REVIEW_MARKDOWN_BYTES) throw new Error('analyst_review_export_size_limit_exceeded');
  const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = ANALYST_REVIEW_MARKDOWN_FILENAME;
  anchor.hidden = true;
  document.body.append(anchor);
  try { anchor.click(); }
  finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
