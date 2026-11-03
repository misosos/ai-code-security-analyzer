import { describe, expect, it, vi } from 'vitest';
import { createReviewMarkdown, downloadReviewMarkdown, escapeMarkdownText, REVIEW_MARKDOWN_FILENAME, type ScanContext } from '../src/features/scans/markdownExport';
import type { ApiFinding, ScanResponse } from '../src/api/types';

const finding: ApiFinding = {
  finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'experimental.command-injection', severity: 'high', verification_status: 'unverified', finding_kind: 'taint',
  file_path: 'src/check.js', line_number: 8, evidence_validation_status: 'validated',
  supported_claims: ['match_reported', 'taint_rule_match_reported'],
  restricted_claims: [{ claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent', 'source_sink_path_unproven'] }], validation_error_code: null,
};
const scan = (overrides: Partial<ScanResponse> = {}): ScanResponse => ({ scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], findings: [finding], limitations: ['finding_count_not_confirmed_vulnerability_count'], ...overrides });
const context: ScanContext = { targetId: 'local-project', targetLabel: 'Local Project', ruleProfileId: 'command-injection-experimental', ruleProfileLabel: 'Command Injection', experimental: true, scanStatus: 'completed', receivedAt: '2026-10-29T01:00:00.000Z' };

describe('UI Markdown export', () => {
  it('exports the received response claims and scope without inventing scan identities', () => {
    const markdown = createReviewMarkdown(context, scan());
    expect(markdown).toContain('보안 분석 검토 보고서');
    expect(markdown).toContain('Local Project (`local-project`)');
    expect(markdown).toContain('Experimental');
    expect(markdown).toContain('KST');
    expect(markdown).toContain('UTC');
    expect(markdown).toContain('Semgrep 매치가 응답에 보고됐습니다.');
    expect(markdown).toContain('구조화된 데이터 흐름 근거가 현재 결과에 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다.');
    expect(markdown).toContain('`flow_trace_available`');
    expect(markdown).toContain('unavailable');
    expect(markdown).toContain('`flow_trace_absent`');
    expect(markdown).toContain('취약점의 발생·확정·수정을 증명하지 않으며');
    expect(markdown).not.toContain('- 취약점 확정 —');
  });


  it('일반 패턴 본문은 반복 제한을 의미별로 묶고 원본 Claim과 사유 코드를 부록에 보존한다', () => {
    const pattern: ApiFinding = {
      ...finding,
      finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa',
      rule_id: 'baseline.javascript-dynamic-eval',
      finding_kind: 'pattern',
      file_path: 'review.js',
      line_number: 2,
      supported_claims: ['match_reported'],
      restricted_claims: [
        { claim_type: 'taint_rule_match_reported', decision: 'unavailable', reason_codes: ['taint_evidence_unavailable'] },
        { claim_type: 'source_pattern_declared', decision: 'unavailable', reason_codes: ['taint_evidence_unavailable'] },
        { claim_type: 'sink_pattern_declared', decision: 'unavailable', reason_codes: ['taint_evidence_unavailable'] },
        { claim_type: 'source_location_identified', decision: 'unavailable', reason_codes: ['source_location_unavailable'] },
        { claim_type: 'sink_argument_location_identified', decision: 'unavailable', reason_codes: ['sink_argument_location_unavailable'] },
        { claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent', 'source_sink_path_unproven'] },
        { claim_type: 'sanitizer_match_observed', decision: 'unavailable', reason_codes: ['sanitizer_match_unavailable'] },
        { claim_type: 'sanitizer_effectiveness_verified', decision: 'insufficient_evidence', reason_codes: ['sanitizer_effectiveness_not_verified'] },
        { claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] },
      ],
    };
    const markdown = createReviewMarkdown(context, scan({ findings: [pattern] }));
    const body = markdown.split('## 5. 기술 상세 부록')[0];
    const appendix = markdown.split('## 5. 기술 상세 부록')[1];
    expect(body).toContain('JavaScript 동적 코드 실행');
    expect(body).toContain('review.js:2');
    expect(body).toContain('이번 일반 패턴 검사 결과에는 신뢰할 수 있는 Source–Sink 흐름 근거가 제공되지 않았습니다.');
    expect(body).toContain('실제 취약점 여부와 악용 가능성은 이 결과만으로 확정되지 않았습니다.');
    expect(body).not.toContain('taint_evidence_unavailable');
    expect(body).not.toContain('flow_trace_absent');
    expect(body.match(/현재 결과에서 확인할 수 없습니다/g)?.length ?? 0).toBeLessThanOrEqual(2);
    expect(appendix).toContain('### Finding `semgrep:aaaaaaaaaaaaaaaaaaaaaaaa`');
    for (const value of ['taint_rule_match_reported', 'source_pattern_declared', 'sink_pattern_declared', 'source_location_identified', 'sink_argument_location_identified', 'flow_trace_available', 'sanitizer_match_observed', 'sanitizer_effectiveness_verified', 'vulnerability_confirmed', 'taint_evidence_unavailable', 'source_location_unavailable', 'sink_argument_location_unavailable', 'flow_trace_absent', 'source_sink_path_unproven', 'sanitizer_match_unavailable', 'sanitizer_effectiveness_not_verified', 'independent_confirmation_required']) {
      expect(appendix).toContain(`\`${value}\``);
    }
  });

  it('Taint Finding은 실제 지원 Claim만 구조적 사실로 구분하고 규칙 선언을 코드 관찰로 바꾸지 않는다', () => {
    const taint: ApiFinding = { ...finding, finding_kind: 'taint', supported_claims: ['taint_rule_match_reported', 'source_pattern_declared'], restricted_claims: [] };
    const markdown = createReviewMarkdown(context, scan({ findings: [taint] }));
    expect(markdown).toContain('신뢰된 Taint 규칙 매치가 보고됐습니다.');
    expect(markdown).toContain('규칙에 Source 패턴이 선언된 사실이 구조적으로 확인됐습니다.');
    expect(markdown).not.toContain('실제 Source 위치가 확인됐습니다.');
    expect(markdown).toContain('취약점 검증 상태:** `unverified`');
    expect(markdown).toContain('`validated`');
  });

  it('보고서에 KST와 원본 UTC를 함께 표시하고 검사 수신 시각으로 한정한다', () => {
    const markdown = createReviewMarkdown(context, scan());
    expect(markdown).toContain('2026-10-29 10:00:00 KST');
    expect(markdown).toContain('2026-10-29T01:00:00.000Z');
    expect(markdown).toContain('실제 검사 실행 시각이나 코드 스냅샷 시각이 아닙니다');
  });

  it('잘못된 브라우저 수신 시각을 현재 시각으로 대체하지 않고 거부한다', () => {
    expect(() => createReviewMarkdown({ ...context, receivedAt: 'not-a-date' }, scan())).toThrow('scan_context_invalid');
  });

  it('동일 규칙의 Finding을 개별 섹션으로 보존하고 unknown 규칙에는 고정된 일반 검토 안내를 제공한다', () => {
    const first = { ...finding, finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', rule_id: 'constructor', file_path: 'one.js', finding_kind: 'unclassified' as const };
    const second = { ...finding, finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', rule_id: 'constructor', file_path: 'two.js', finding_kind: 'unclassified' as const };
    const markdown = createReviewMarkdown(context, scan({ findings: [second, first], finding_count: 2, displayed_finding_count: 2, severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 } }));
    expect(markdown.match(/### 분류되지 않은 Finding 검토/g)).toHaveLength(2);
    expect(markdown).toContain('one.js:8');
    expect(markdown).toContain('two.js:8');
    expect(markdown).toContain('constructor');
    expect(markdown).toContain('규칙 ID, 매치 위치와 근거 연결 상태를 확인합니다.');
  });

  it('분류되지 않은 Finding을 Pattern 또는 Taint로 추정하지 않는다', () => {
    const unclassified: ApiFinding = {
      ...finding, finding_id: 'semgrep:cccccccccccccccccccccccc', finding_kind: 'unclassified',
      supported_claims: ['match_reported'],
      restricted_claims: [{ claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent'] }],
    };
    const markdown = createReviewMarkdown(context, scan({ findings: [unclassified] }));
    expect(markdown).toContain('분류되지 않은 Finding 검토');
    expect(markdown).toContain('Finding 유형이 분류되지 않아 Source–Sink 흐름 근거');
    expect(markdown).not.toContain('Taint 흐름 검토 후보');
    expect(markdown).toContain('`flow_trace_absent`');
  });

  it('코드 표시용 문자열에서 Markdown 구분자와 Unicode 제어문자를 실행 불가능하게 보존한다', () => {
    const attacked = { ...finding, file_path: 'src/`<script>.js' };
    const markdown = createReviewMarkdown(context, scan({ findings: [attacked] }));
    expect(markdown).toContain('``src/`<script>.js:8``');
    expect(markdown).not.toContain('\n<script>');
  });

  it('does not promote claims when consumer validation is rejected', () => {
    const rejected = { ...finding, evidence_validation_status: 'rejected' as const, supported_claims: [], validation_error_code: 'evidence_unavailable' };
    const markdown = createReviewMarkdown(context, scan({ findings: [rejected] }));
    expect(markdown).toContain('근거 검증에 실패했거나 사용할 수 없어 지원된 주장을 표시하지 않습니다.');
    expect(markdown).not.toContain('Semgrep 규칙 매치 보고');
  });

  it('retains failed/partial status, zero results and omitted-finding warning', () => {
    const partial = { ...context, scanStatus: 'partial' as const };
    const text = createReviewMarkdown(partial, scan({ scan_status: 'partial', completed: false, finding_count: 3, displayed_finding_count: 1, omitted_finding_count: 2, severity_counts: { critical: 0, high: 3, medium: 0, low: 0, info: 0 }, limitations: ['scan_partial', 'omitted_findings_not_individually_validated'] }));
    expect(text).toContain('부분 검사');
    expect(text).toContain('전체 Finding: 3');
    expect(text).toContain('포함된 Finding: 1');
    expect(text).toContain('생략: 2');
    expect(text).toContain('개별 위치와 근거는 이 보고서에서 검토되지 않았습니다');
    const empty = createReviewMarkdown(context, scan({ finding_count: 0, displayed_finding_count: 0, findings: [], severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }));
    expect(empty).toContain('탐지 0건은 코드가 안전하다는 증명');
    const failedContext = { ...context, scanStatus: 'timed_out' as const };
    expect(createReviewMarkdown(failedContext, scan({ scan_status: 'timed_out', completed: false, findings: [], finding_count: 0, displayed_finding_count: 0, severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, limitations: ['scan_failed'] }))).toContain('검사 상태: 시간 초과 · completed=false');
  });

  it('encodes Markdown, HTML, control, bidi and line-breaking syntax', () => {
    const attack = '# title\n[link](https://bad) ![image](https://bad) <script>alert(1)</script> ```\u202E\u001b';
    const escaped = escapeMarkdownText(attack);
    expect(escaped).not.toContain('<script>');
    expect(escaped).not.toContain('\n');
    expect(escaped).toContain('&#x23;');
    expect(escaped).toContain('&#x202E;');
    const safeAttack = '# title [link](https://bad) ![image](https://bad) <script>alert(1)</script> ```';
    const injected = createReviewMarkdown({ ...context, targetLabel: safeAttack }, scan({ findings: [{ ...finding, file_path: 'src/<script>.js' }] }));
    expect(injected).not.toContain('# title');
    expect(injected).not.toContain('\n<script>');
    expect(injected).not.toContain('\n[link]');
    expect(injected).not.toContain('![image]');
    expect(injected).toContain('&#x23;');
    expect(injected).toContain('`src/<script>.js:8`');
  });

  it('rejects context mismatch and output beyond the UTF-8 byte cap', () => {
    expect(() => createReviewMarkdown({ ...context, scanStatus: 'partial' }, scan())).toThrow('scan_context_mismatch');
    const huge = { ...finding, file_path: '가'.repeat(180_000) };
    expect(() => createReviewMarkdown(context, scan({ findings: [huge] }))).toThrow('export_size_limit_exceeded');
  });

  it('rejects token/code extra fields and absolute paths at the validated API boundary', () => {
    const token = 'synthetic-token-must-not-appear';
    expect(() => createReviewMarkdown(context, { ...scan(), api_token: token } as unknown as ScanResponse)).toThrow('scan_response_invalid');
    expect(() => createReviewMarkdown(context, scan({ findings: [{ ...finding, source_code: 'synthetic source must not appear' } as ApiFinding] }))).toThrow('scan_response_invalid');
    expect(() => createReviewMarkdown(context, scan({ findings: [{ ...finding, file_path: '/private/synthetic/review.js' }] }))).toThrow('scan_response_invalid');
  });

  it('creates a fixed-name local download and revokes its object URL', () => {
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:local-test');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    vi.useFakeTimers();
    downloadReviewMarkdown('# summary');
    expect(create).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    const anchor = document.querySelector('a[download]');
    expect(anchor).toBeNull();
    expect(REVIEW_MARKDOWN_FILENAME).toBe('ai-code-security-ui-review-summary.md');
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:local-test');
    vi.useRealTimers();
  });
});
