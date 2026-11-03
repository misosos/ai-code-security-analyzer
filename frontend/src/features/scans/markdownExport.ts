import { parseScan, type ApiFinding, type ClaimDecision, type ClaimType, type FindingKind, type ScanResponse } from '../../api/types';
import { getFindingReviewGuidance, hasKnownRuleGuidance } from './reviewGuidance';

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

const statusLabels: Record<ScanResponse['scan_status'], string> = {
  completed: '정상 완료', partial: '부분 검사', execution_failed: '실행 실패', not_installed: 'Semgrep 미설치',
  invalid_json: '결과 형식 오류', timed_out: '시간 초과', output_limit_exceeded: '출력 제한 초과',
};
const severityLabels: Record<keyof ScanResponse['severity_counts'], string> = {
  critical: '매우 높음', high: '높음', medium: '중간', low: '낮음', info: '정보',
};
const kindLabels: Record<FindingKind, string> = { taint: 'Taint', pattern: '일반 패턴', unclassified: '분류되지 않음' };
const claimLabels: Record<ClaimType, string> = {
  match_reported: '규칙 매치', taint_rule_match_reported: 'Taint 규칙 매치',
  source_pattern_declared: '규칙의 Source 패턴 선언', sink_pattern_declared: '규칙의 Sink 패턴 선언',
  match_location_observed: '보고된 매치 위치', source_location_identified: '실제 Source 위치',
  sink_argument_location_identified: 'Sink 인자 위치', flow_trace_available: '구조화된 흐름 trace',
  sanitizer_match_observed: 'Sanitizer 매치', sanitizer_effectiveness_verified: 'Sanitizer 효과',
  vulnerability_confirmed: '취약점 확정',
};
const decisionLabels: Record<ClaimDecision, string> = {
  unavailable: '현재 결과에서 확인할 수 없습니다',
  insufficient_evidence: '근거가 판단을 뒷받침하기에 충분하지 않습니다',
  ambiguous: '근거와 Finding의 연결이 모호합니다',
  unsupported_claim: '현재 분석 정책에서 지원하지 않는 주장입니다',
};
const issueLabels: Record<string, string> = {
  semgrep_not_installed: 'Semgrep을 사용할 수 없습니다.', semgrep_timeout: 'Semgrep 실행 시간이 제한을 초과했습니다.',
  semgrep_output_limit: 'Semgrep 출력이 허용된 크기 제한을 초과했습니다.', invalid_json: 'Semgrep 결과 형식을 읽을 수 없습니다.',
  semgrep_failed: 'Semgrep 실행이 정상 완료되지 않았습니다.', findings_omitted: '응답 크기 제한으로 일부 Finding이 생략됐습니다.',
  evidence_unavailable: '일부 Finding의 근거 연결을 검증할 수 없었습니다.',
};
const limitationLabels: Record<string, string> = {
  finding_count_not_confirmed_vulnerability_count: 'Finding 수는 취약점 확정 수가 아닙니다.',
  scan_result_is_not_safety_proof: '검사 결과는 코드 안전성의 증명이 아닙니다.',
  scan_partial: '검사가 일부 범위에서만 완료됐습니다.', scan_failed: '검사가 실패했거나 완료되지 않았습니다.',
  omitted_findings_not_individually_validated: '생략된 Finding의 개별 근거는 검증되지 않았습니다.',
};

const taintFlowClaims = new Set<ClaimType>([
  'taint_rule_match_reported', 'source_pattern_declared', 'sink_pattern_declared', 'source_location_identified',
  'sink_argument_location_identified', 'flow_trace_available',
]);

// Plain prose uses the existing entity escaping policy. Machine identifiers and paths
// use a separate inline-code serializer so underscores remain readable without opening
// Markdown structure. The delimiter is longer than every backtick run in the value.
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

function codeSpan(value: string): string {
  const visible = Array.from(value, (char) => /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(char)
    ? `\\u{${char.codePointAt(0)!.toString(16).toUpperCase()}}` : char).join('');
  let longestRun = 0;
  for (const match of visible.matchAll(/`+/g)) longestRun = Math.max(longestRun, match[0].length);
  const delimiter = '`'.repeat(longestRun + 1);
  const needsPadding = visible.startsWith(' ') || visible.endsWith(' ') || visible.startsWith('`') || visible.endsWith('`');
  const content = needsPadding ? ` ${visible} ` : visible;
  return `${delimiter}${content}${delimiter}`;
}

function prose(value: string): string { return escapeMarkdownText(value); }

function validateContext(context: ScanContext, scan: ScanResponse): void {
  const absolutePathLabel = (value: string) => value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value)
    || value.startsWith('\\\\') || value.startsWith('~/');
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

function safeRelativePath(path: string | null): string {
  if (path === null) return '위치 확인 불가';
  if (!path || path.startsWith('/') || path.startsWith('\\\\') || /^[A-Za-z]:/.test(path) || path.includes('\\')
    || /[\p{C}]/u.test(path) || path.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error('scan_response_invalid');
  }
  return path;
}

function receivedAtKst(iso: string): string {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) throw new Error('scan_context_invalid');
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((item) => item.type === type)?.value ?? '';
  return `${part('year')}-${part('month')}-${part('day')} ${part('hour')}:${part('minute')}:${part('second')} KST`;
}

function issueText(code: string): string { return Object.hasOwn(issueLabels, code) ? issueLabels[code] : '검사 처리 과정에서 안내가 발생했습니다.'; }
function limitationText(code: string): string { return Object.hasOwn(limitationLabels, code) ? limitationLabels[code] : '검사 범위에 제한이 있습니다.'; }

function titleAndFindingText(finding: ApiFinding): { title: string; text: string } {
  const guidance = getFindingReviewGuidance(finding.rule_id, finding.finding_kind);
  return { title: guidance.title, text: guidance.finding };
}

function supportedFact(claim: ClaimType): string {
  const labels: Record<ClaimType, string> = {
    match_reported: 'Semgrep 매치가 응답에 보고됐습니다.',
    taint_rule_match_reported: '신뢰된 Taint 규칙 매치가 보고됐습니다.',
    source_pattern_declared: '규칙에 Source 패턴이 선언된 사실이 구조적으로 확인됐습니다. 실제 코드의 Source 위치 확인과는 다릅니다.',
    sink_pattern_declared: '규칙에 Sink 패턴이 선언된 사실이 구조적으로 확인됐습니다. 실제 코드의 Sink 위치 확인과는 다릅니다.',
    match_location_observed: '보고된 매치 위치가 검사 결과에 연결됐습니다.',
    source_location_identified: '실제 Source 위치가 식별됐습니다.',
    sink_argument_location_identified: 'Sink 인자 위치가 식별됐습니다.',
    flow_trace_available: '구조화된 흐름 Trace가 결과에 제공됐습니다.',
    sanitizer_match_observed: 'Sanitizer 패턴 매치가 관찰됐습니다. 이것만으로 정제 효과가 입증되지는 않습니다.',
    sanitizer_effectiveness_verified: 'Sanitizer 효과가 구조적으로 검증됐다고 API가 보고했습니다.',
    vulnerability_confirmed: 'API 응답에 취약점 확정 주장이 포함됐습니다. 이 UI 보고서는 이를 독립 검증하지 않습니다.',
  };
  return labels[claim];
}

function restrictionSentence(type: ClaimType, decision: ClaimDecision): string {
  if (type === 'vulnerability_confirmed') {
    if (decision === 'unavailable') return '취약점 확정 여부를 현재 결과에서 확인할 수 없습니다.';
    if (decision === 'insufficient_evidence') return '취약점 확정에는 추가 근거가 필요합니다.';
    if (decision === 'ambiguous') return '취약점 확정 주장을 Finding에 연결할 근거가 모호합니다.';
    return '정적 분석 결과만으로 취약점을 확정하지 않습니다.';
  }
  return `${claimLabels[type]}: ${decisionLabels[decision]}.`;
}

function mainLimitations(finding: ApiFinding): string[] {
  const output: string[] = [];
  const grouped = new Map<ClaimDecision, Set<ClaimType>>();
  const flowDecisionGroups = new Set<ClaimDecision>();
  for (const item of finding.restricted_claims) {
    if (taintFlowClaims.has(item.claim_type)) {
      flowDecisionGroups.add(item.decision);
      continue;
    }
    const types = grouped.get(item.decision) ?? new Set<ClaimType>();
    types.add(item.claim_type);
    grouped.set(item.decision, types);
  }
  for (const decision of ['unavailable', 'insufficient_evidence', 'ambiguous', 'unsupported_claim'] as const) {
    if (flowDecisionGroups.has(decision)) {
      const patternSummary: Record<ClaimDecision, string> = {
        unavailable: '이번 일반 패턴 검사 결과에는 신뢰할 수 있는 Source–Sink 흐름 근거가 제공되지 않았습니다. 실제 흐름이 없다는 뜻은 아닙니다.',
        insufficient_evidence: '이번 일반 패턴 검사 결과의 Source–Sink 흐름 근거는 판단을 뒷받침하기에 충분하지 않습니다.',
        ambiguous: '이번 일반 패턴 검사 결과의 Source–Sink 흐름 근거가 Finding과 어떻게 연결되는지 모호합니다.',
        unsupported_claim: '현재 정책은 이번 일반 패턴 결과에서 Source–Sink 흐름 주장을 지원하지 않습니다.',
      };
      const taintSummary: Record<ClaimDecision, string> = {
        unavailable: '구조화된 데이터 흐름 근거가 현재 결과에 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다.',
        insufficient_evidence: '제공된 데이터 흐름 근거만으로는 Source에서 Sink까지의 경로를 판단하기에 충분하지 않습니다.',
        ambiguous: '데이터 흐름 근거와 Finding의 연결이 모호하여 경로를 확정할 수 없습니다.',
        unsupported_claim: '현재 분석 정책은 이 결과만으로 해당 데이터 흐름 주장을 지원하지 않습니다.',
      };
      const unclassifiedSummary: Record<ClaimDecision, string> = {
        unavailable: 'Finding 유형이 분류되지 않아 Source–Sink 흐름 근거를 현재 결과에서 확인할 수 없습니다. 흐름이 없다는 뜻은 아닙니다.',
        insufficient_evidence: '분류되지 않은 Finding의 흐름 근거는 판단을 뒷받침하기에 충분하지 않습니다.',
        ambiguous: '분류되지 않은 Finding의 흐름 근거와 항목 연결이 모호합니다.',
        unsupported_claim: '현재 분석 정책은 분류되지 않은 Finding의 Source–Sink 흐름 주장을 지원하지 않습니다.',
      };
      output.push(finding.finding_kind === 'pattern' ? patternSummary[decision]
        : finding.finding_kind === 'taint' ? taintSummary[decision] : unclassifiedSummary[decision]);
    }
    const types = grouped.get(decision);
    if (!types) continue;
    if (types.size === 1) {
      const [type] = types;
      output.push(restrictionSentence(type, decision));
    } else {
      output.push(`${[...types].map((type) => claimLabels[type]).join(', ')}: ${decisionLabels[decision]}.`);
    }
  }
  return [...new Set(output)];
}

function findingBody(finding: ApiFinding): string[] {
  const location = `${safeRelativePath(finding.file_path)}${finding.line_number === null ? '' : `:${finding.line_number}`}`;
  const display = titleAndFindingText(finding);
  const lines = [
    `### ${prose(display.title)}`,
    '', `**Finding ID:** ${codeSpan(finding.finding_id)}`,
    `**탐지 위치:** ${codeSpan(location)}`,
    `**규칙 ID:** ${codeSpan(finding.rule_id)}`,
    `**도구 심각도:** ${prose(finding.severity)} · **탐지 유형:** ${kindLabels[finding.finding_kind]}`,
    `**취약점 검증 상태:** ${codeSpan(finding.verification_status)} · **근거 연결:** ${codeSpan(finding.evidence_validation_status)}`,
    '', '#### 탐지 결과', '', display.text, '', '#### 구조적으로 확인된 사실',
  ];
  if (finding.evidence_validation_status === 'validated') {
    if (finding.supported_claims.length) for (const claim of finding.supported_claims) lines.push(`- ${supportedFact(claim)}`);
    else lines.push('- 지원된 구조적 Claim이 없습니다.');
    lines.push('- `validated`는 보고된 매치와 근거의 구조적 연결 검증 상태이며 취약점 확인이 아닙니다.');
  } else {
    lines.push(`- 근거 연결은 \`${finding.evidence_validation_status}\` 상태입니다. 근거 검증에 실패했거나 사용할 수 없어 지원된 주장을 표시하지 않습니다.`);
    lines.push('- 지원 Claim과 제한 Claim의 원본 상태는 기술 상세 부록에서 확인할 수 있습니다.');
  }
  lines.push('', '#### 아직 확인되지 않은 사항', '- 실제 취약점 여부와 악용 가능성은 이 결과만으로 확정되지 않았습니다.');
  if (finding.verification_status === 'unverified') lines.push('- 취약점 검증 상태는 `unverified`입니다.');
  for (const limitation of mainLimitations(finding)) lines.push(`- ${limitation}`);
  const guidance = getFindingReviewGuidance(finding.rule_id, finding.finding_kind);
  lines.push('', '#### 권장 추가 검토', ...guidance.tasks.map((task, taskIndex) => `${taskIndex + 1}. ${task}`));
  lines.push('', '#### 검토 시 고려할 조치 방향', ...guidance.actions.map((action) => `- ${action}`));
  lines.push('', '#### 보안적 해석의 한계', '이 항목은 도구가 보고한 검토 후보입니다. 줄 이동, 입력 출처, 실행 경로, 방어 조건 및 운영 환경을 직접 확인하기 전까지 취약점 확정이나 수정 완료로 해석하지 않습니다.');
  return lines;
}

function technicalAppendix(finding: ApiFinding): string[] {
  const lines = [
    `### Finding ${codeSpan(finding.finding_id)}`,
    `- Rule ID: ${codeSpan(finding.rule_id)}`,
    `- finding_kind: ${codeSpan(finding.finding_kind)}`,
    `- severity: ${codeSpan(finding.severity)}`,
    `- verification_status: ${codeSpan(finding.verification_status)}`,
    `- evidence_validation_status: ${codeSpan(finding.evidence_validation_status)}`,
    `- validation_error_code: ${finding.validation_error_code === null ? '없음' : codeSpan(finding.validation_error_code)}`,
    '- supported_claims:',
  ];
  if (finding.supported_claims.length) lines.push(...finding.supported_claims.map((claim) => `  - ${codeSpan(claim)}`));
  else lines.push('  - 없음');
  lines.push('- restricted_claims:');
  if (finding.restricted_claims.length) {
    for (const item of finding.restricted_claims) {
      lines.push(`  - claim_type: ${codeSpan(item.claim_type)}`, `    decision: ${codeSpan(item.decision)}`, '    reason_codes:');
      if (item.reason_codes.length) lines.push(...item.reason_codes.map((reason) => `      - ${codeSpan(reason)}`));
      else lines.push('      - 없음');
    }
  } else lines.push('  - 없음');
  return lines;
}

export function createReviewMarkdown(context: ScanContext, input: ScanResponse): string {
  let scan: ScanResponse;
  try { scan = parseScan(input); } catch { throw new Error('scan_response_invalid'); }
  validateContext(context, scan);
  const findings = [...scan.findings].sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  const ruleIds = [...new Set(findings.map((item) => item.rule_id))].sort((left, right) => left.localeCompare(right));
  const linkedEvidenceCount = findings.filter((finding) => finding.evidence_validation_status === 'validated').length;
  const sections = [
    '# AI Code Security Analyzer — 보안 분석 검토 보고서',
    '', '> 이 문서는 UI에서 받은 정적 분석 결과를 실무 검토용으로 정리합니다. Finding의 변화나 검토 제안은 취약점의 발생·확정·수정을 증명하지 않으며 CLI의 정식 `review-md` 보고서를 대체하지 않습니다.',
    '', '## 1. 검사 개요',
    `- 검사 대상: ${prose(context.targetLabel)} (${codeSpan(context.targetId)})`,
    `- 규칙 프로필: ${prose(context.ruleProfileLabel)} · ID ${codeSpan(context.ruleProfileId)} · ${context.experimental ? 'Experimental' : 'Baseline'}`,
    `- Semgrep 버전: ${scan.semgrep_version ? codeSpan(scan.semgrep_version) : '확인 불가'}`,
    `- 검사 상태: ${statusLabels[scan.scan_status]} · completed=${scan.completed ? 'true' : 'false'}`,
    `- 결과 수신: ${receivedAtKst(context.receivedAt)}`,
    `- 원본 UTC 수신 시각: ${codeSpan(new Date(context.receivedAt).toISOString())}`,
    '- 위 시각은 브라우저가 응답을 받은 시각이며 실제 검사 실행 시각이나 코드 스냅샷 시각이 아닙니다. 파일 수정 시각도 아닙니다.',
    `- 전체 Finding: ${scan.finding_count} · 표시: ${scan.displayed_finding_count} · 포함된 Finding: ${scan.displayed_finding_count} · 생략: ${scan.omitted_finding_count}`,
    '', '### 검사 범위 및 주의사항',
    '- `high` 등 심각도는 도구의 우선순위 분류이며 실제 악용 가능성을 확인한 결과가 아닙니다.',
    '- 모든 Finding의 `verification_status`는 응답에 기록된 상태 그대로이며 이 보고서에서 재판정하지 않습니다.',
  ];
  if (scan.scan_status === 'partial') sections.push('- 부분 검사입니다. 완료되지 않은 범위가 있을 수 있으므로 전체 검사 결과로 해석하지 마세요.');
  else if (!scan.completed) sections.push('- 검사가 정상 완료되지 않았습니다. 응답에 포함된 정보만 기록하며 완전한 결과를 뜻하지 않습니다.');
  if (scan.omitted_finding_count > 0) sections.push(`- 생략 경고: ${scan.omitted_finding_count}개 Finding의 개별 위치와 근거는 이 보고서에서 검토되지 않았습니다.`);
  if (scan.issues.length) sections.push('', '### 검사 처리 안내', ...[...new Set(scan.issues)].map((issue) => `- ${issueText(issue)}`));
  if (scan.limitations.length) sections.push('', '### 검사 범위 제한', ...[...new Set(scan.limitations)].map((limitation) => `- ${limitationText(limitation)}`));
  sections.push(
    '', '## 2. 검사 결과 요약',
    `- 검토 후보: ${scan.finding_count}건 · 취약점 확정 수가 아닙니다.`,
    `- 표시된 결과: ${scan.displayed_finding_count}건 · 현재 응답에 포함된 Finding입니다.`,
    `- 생략된 결과: ${scan.omitted_finding_count}건 · 개별 근거를 확인하지 못했습니다.`,
    '', '### 심각도별 탐지 수',
    ...(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => `- ${severityLabels[severity]} (${severity}): ${scan.severity_counts[severity]}`),
    '', '### 주요 탐지 규칙',
    ...(ruleIds.length ? ruleIds.map((ruleId) => {
      const guidance = hasKnownRuleGuidance(ruleId) ? getFindingReviewGuidance(ruleId, findings.find((item) => item.rule_id === ruleId)!.finding_kind) : undefined;
      return `- ${codeSpan(ruleId)}${guidance ? ` · ${prose(guidance.title)}` : ''}`;
    }) : ['- 표시된 Finding이 없습니다.']),
    '', `- 근거 연결이 \`validated\`인 표시 Finding: ${linkedEvidenceCount}/${findings.length}건. 구조적 연결 상태이며 취약점 검증과는 다릅니다.`,
    '- 아직 확인되지 않은 사항: 실제 입력 도달성, Source–Sink 실행 경로, 방어 조건의 효과, 악용 가능성 및 운영 환경은 코드 검토 없이 확정할 수 없습니다.',
    '', '## 3. Finding별 보안 검토',
  );
  if (!findings.length) sections.push('', '응답에 표시된 Finding이 없습니다. 탐지 0건은 코드가 안전하다는 증명이나 전체 파일 검사의 증거가 아닙니다.');
  findings.forEach((finding, index) => {
    if (index > 0) sections.push('');
    sections.push(...findingBody(finding));
  });
  sections.push(
    '', '## 4. 공통 분석 한계',
    '- 정적 분석 결과는 규칙과 일치한 관찰 후보입니다. 취약점 확정에는 코드 맥락, 입력 출처, 실행 경로와 방어 조건의 별도 검토가 필요합니다.',
    '- `validated`는 응답에 포함된 매치와 근거의 구조적 연결 검증입니다. 실제 취약점, 악용 가능성 또는 수정 상태를 확인하지 않습니다.',
    '- `unavailable`은 현재 결과에서 근거를 얻지 못했다는 뜻이며 해당 흐름이나 방어가 없다는 뜻이 아닙니다.',
    '- 규칙 선언, Semgrep 매치 위치, 실제 코드의 Source/Sink 위치와 런타임 동작은 서로 다른 근거입니다.',
    '- 줄 이동, 코드 변경, 파일 이동 또는 규칙 변경은 Finding 분류에 영향을 줄 수 있습니다.',
    '- 이 UI 요약은 CLI의 정식 `review-md` 보고서를 대체하지 않습니다.',
    '', '## 5. 기술 상세 부록',
    '> 아래에는 각 Finding의 원본 Claim·Decision·Reason Code를 응답 그대로 보존합니다. 본문 요약과 별개로 추적할 수 있습니다.',
  );
  if (!findings.length) sections.push('', '부록에 기록할 Finding Claim이 없습니다.');
  findings.forEach((finding, index) => {
    if (index > 0) sections.push('');
    sections.push(...technicalAppendix(finding));
  });
  const markdown = `${sections.join('\n')}\n`;
  if (new TextEncoder().encode(markdown).byteLength > MAX_REVIEW_MARKDOWN_BYTES) throw new Error('export_size_limit_exceeded');
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
