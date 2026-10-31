import type { ApiFinding, ClaimType, ScanStatus } from '../../api/types';
import { compareScanSnapshots, type ScanSnapshot } from './compare';
import { escapeMarkdownText } from './markdownExport';

export const MAX_COMPARISON_MARKDOWN_BYTES = 512 * 1024;
export const COMPARISON_MARKDOWN_FILENAME = 'ai-code-security-comparison.md';

const statusLabels: Record<ScanStatus, string> = {
  completed: '정상 완료', partial: '부분 검사', execution_failed: '실행 실패', not_installed: 'Semgrep 미설치',
  invalid_json: '결과 형식 오류', timed_out: '시간 초과', output_limit_exceeded: '출력 제한 초과',
};
const kindLabels = { taint: 'Taint', pattern: '일반 패턴', unclassified: '분류되지 않음' } as const;
const claimLabels: Record<ClaimType, string> = {
  match_reported: '규칙 매치 보고', taint_rule_match_reported: 'Taint 규칙 매치 보고',
  source_pattern_declared: '규칙의 Source 패턴 선언', sink_pattern_declared: '규칙의 Sink 패턴 선언',
  match_location_observed: '매치 위치 관찰', source_location_identified: '실제 Source 위치 식별',
  sink_argument_location_identified: 'Sink 인자 위치 식별', flow_trace_available: '구조화된 흐름 Trace 제공',
  sanitizer_match_observed: 'Sanitizer 매치 관찰', sanitizer_effectiveness_verified: 'Sanitizer 효과 검증',
  vulnerability_confirmed: '취약점 확정',
};

function text(value: string): string { return escapeMarkdownText(value); }
function date(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '시간 정보 확인 불가' : text(parsed.toISOString());
}
function safeRelativePath(value: string | null): string {
  if (!value) return '파일 위치 확인 불가';
  // Defense in depth: API parsing rejects absolute paths, but never serialize one if
  // this pure exporter is called with a malformed snapshot from another caller.
  if (value.startsWith('/') || value.startsWith('\\\\') || /^[A-Za-z]:/.test(value) || value.includes('\\')
    || value.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    return '절대 경로는 보고서에서 제외';
  }
  return text(value);
}
function claim(value: ClaimType): string { return `${text(claimLabels[value])} (${text(value)})`; }

function findingDetails(finding: ApiFinding): string[] {
  const location = `${safeRelativePath(finding.file_path)}${finding.line_number === null ? '' : `:${finding.line_number}`}`;
  const lines = [
    `- Finding ID: ${text(finding.finding_id)}`,
    `- 규칙 ID: ${text(finding.rule_id)}`,
    `- 심각도 / 탐지 유형: ${text(finding.severity)} / ${kindLabels[finding.finding_kind]}`,
    `- 위치: ${location}`,
    `- 검증 상태: ${text(finding.verification_status)}`,
    `- 근거 연결 상태: ${text(finding.evidence_validation_status)}`,
  ];
  if (finding.validation_error_code) lines.push(`- 근거 검증 코드: ${text(finding.validation_error_code)}`);
  lines.push('- 지원된 주장:');
  if (finding.supported_claims.length) finding.supported_claims.forEach((item) => lines.push(`  - ${claim(item)}`));
  else lines.push('  - 없음');
  lines.push('- 제한된 주장 및 사유 코드:');
  if (finding.restricted_claims.length) {
    for (const item of finding.restricted_claims) {
      lines.push(`  - ${claim(item.claim_type)} — ${text(item.decision)}`);
      if (item.reason_codes.length) lines.push(`    - 사유 코드: ${item.reason_codes.map(text).join(', ')}`);
    }
  } else lines.push('  - 없음');
  return lines;
}

function singleFindingSection(title: string, findings: ApiFinding[]): string[] {
  const lines = [`## ${title}`, ''];
  if (!findings.length) return [...lines, '해당하는 Finding이 없습니다.', ''];
  findings.forEach((finding, index) => {
    lines.push(`### 항목 ${index + 1}`, '', ...findingDetails(finding), '');
  });
  return lines;
}

function sharedFindingSection(baseline: ApiFinding[], current: ApiFinding[]): string[] {
  const lines = ['## 양쪽 검사에서 관찰', ''];
  if (!current.length) return [...lines, '양쪽에서 관찰된 Finding이 없습니다.', ''];
  const baselineById = new Map(baseline.map((finding) => [finding.finding_id, finding]));
  current.forEach((currentFinding, index) => {
    const baselineFinding = baselineById.get(currentFinding.finding_id)!;
    lines.push(`### 공통 항목 ${index + 1}`, '', `- 공통 Finding ID: ${text(currentFinding.finding_id)}`, '', '#### 기준 검사 메타데이터', ...findingDetails(baselineFinding), '', '#### 현재 검사 메타데이터', ...findingDetails(currentFinding), '', '동일 ID는 보고된 위치 ID의 일치만 뜻하며 코드나 보안 상태가 동일함을 증명하지 않습니다.', '');
  });
  return lines;
}

/** Build a complete report only when the Phase 8A comparison contract is satisfied. */
export function createComparisonMarkdown(baseline: ScanSnapshot | null, current: ScanSnapshot | null): string {
  const comparison = compareScanSnapshots(baseline, current);
  if (!comparison.comparable || !comparison.groups || !baseline || !current) {
    throw new Error('comparison_not_exportable');
  }
  const groups = comparison.groups;
  const sections = [
    '# AI Code Security Analyzer — 검사 결과 비교 보고서',
    '',
    '> 이 문서는 두 정적 분석 검사에서 관찰된 Finding 차이를 비교합니다. Finding의 변화는 실제 취약점의 발생·해결 또는 수정 완료를 증명하지 않습니다.',
    '', '## 검사 문맥',
    `- 기준 검사 대상: ${text(baseline.context.targetLabel)} (${text(baseline.context.targetId)})`,
    `- 현재 검사 대상: ${text(current.context.targetLabel)} (${text(current.context.targetId)})`,
    `- 기준 규칙 프로필: ${text(baseline.context.ruleProfileLabel)} (${text(baseline.context.ruleProfileId)})${baseline.context.experimental ? ' · Experimental' : ' · Baseline'}`,
    `- 현재 규칙 프로필: ${text(current.context.ruleProfileLabel)} (${text(current.context.ruleProfileId)})${current.context.experimental ? ' · Experimental' : ' · Baseline'}`,
    `- Semgrep 버전: ${text(baseline.scan.semgrep_version!)}`,
    `- 기준 검사 상태: ${statusLabels[baseline.scan.scan_status]}`,
    `- 현재 검사 상태: ${statusLabels[current.scan.scan_status]}`,
    `- 기준 결과 수신 시각 (브라우저 기록, ISO 8601): ${date(baseline.context.receivedAt)}`,
    `- 현재 결과 수신 시각 (브라우저 기록, ISO 8601): ${date(current.context.receivedAt)}`,
    '',
    '> 수신 시각은 브라우저가 응답을 받은 시각이며, 실제 검사 실행 시각이나 코드 스냅샷 시각이 아닙니다.',
    '', '## 비교 요약',
    `- 기준 검사 Finding 총수: ${baseline.scan.finding_count}`,
    `- 현재 검사 Finding 총수: ${current.scan.finding_count}`,
    `- 이번 검사에서만 관찰: ${groups.currentOnly.length}`,
    `- 양쪽에서 관찰: ${groups.shared.length}`,
    `- 기준 검사에서만 관찰: ${groups.baselineOnly.length}`,
    '',
    ...singleFindingSection('이번 검사에서만 관찰', groups.currentOnly),
    ...sharedFindingSection(baseline.scan.findings, groups.shared),
    ...singleFindingSection('기준 검사에서만 관찰', groups.baselineOnly),
    '## 분석 한계와 후속 검토',
    '',
    '- Finding ID는 규칙 및 코드 위치 기반 식별자입니다. 줄 이동이나 파일·규칙 변경으로 분류가 달라질 수 있습니다.',
    '- 이번 검사에서만 관찰된 항목은 새 취약점의 발생을 의미하지 않습니다.',
    '- 기준 검사에서만 관찰된 항목은 취약점 해결 또는 수정 완료를 의미하지 않습니다.',
    '- `unverified`는 취약점이 확정되지 않았다는 뜻입니다. `validated`는 근거 연결의 구조적 검증 상태이며 취약점 확인을 뜻하지 않습니다.',
    '- 정적 분석은 실제 악용 가능성이나 코드 안전성을 증명하지 않습니다. 파일 위치와 근거를 수동으로 검토하세요.',
    '- 이 비교 요약은 CLI의 정식 보안 검토 보고서를 대체하지 않습니다.',
  ];
  const markdown = `${sections.join('\n')}\n`;
  if (new TextEncoder().encode(markdown).byteLength > MAX_COMPARISON_MARKDOWN_BYTES) {
    throw new Error('comparison_export_size_limit_exceeded');
  }
  return markdown;
}

export function downloadComparisonMarkdown(markdown: string): void {
  if (new TextEncoder().encode(markdown).byteLength > MAX_COMPARISON_MARKDOWN_BYTES) {
    throw new Error('comparison_export_size_limit_exceeded');
  }
  const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = COMPARISON_MARKDOWN_FILENAME;
  anchor.hidden = true;
  try { document.body.append(anchor); anchor.click(); }
  finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
