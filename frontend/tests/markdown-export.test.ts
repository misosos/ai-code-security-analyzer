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
    expect(markdown).toContain('UI Analyst Review Summary');
    expect(markdown).toContain('Local Project (local-project)');
    expect(markdown).toContain('Experimental');
    expect(markdown).toContain('브라우저 로컬 기록');
    expect(markdown).toContain('Semgrep 규칙 매치 보고');
    expect(markdown).toContain('구조화된 데이터 흐름 trace가 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다.');
    expect(markdown).toContain('(flow&#x5F;trace&#x5F;available) — 현재 자료에서 확인 불가 (unavailable)');
    expect(markdown).toContain('(flow&#x5F;trace&#x5F;absent)');
    expect(markdown).toContain('취약점 확정 문서가 아니며');
    expect(markdown).not.toContain('- 취약점 확정 —');
  });

  it('does not promote claims when consumer validation is rejected', () => {
    const rejected = { ...finding, evidence_validation_status: 'rejected' as const, supported_claims: [], validation_error_code: 'evidence_unavailable' };
    const markdown = createReviewMarkdown(context, scan({ findings: [rejected] }));
    expect(markdown).toContain('근거 검증에 실패했거나 사용할 수 없어 지원된 주장을 표시하지 않습니다.');
    expect(markdown).not.toContain('Semgrep 규칙 매치 보고');
  });

  it('retains failed/partial status, zero results and omitted-finding warning', () => {
    const partial = { ...context, scanStatus: 'partial' as const };
    const text = createReviewMarkdown(partial, scan({ scan_status: 'partial', completed: false, finding_count: 3, displayed_finding_count: 1, omitted_finding_count: 2, limitations: ['scan_partial', 'omitted_findings_not_individually_validated'] }));
    expect(text).toContain('부분 검사');
    expect(text).toContain('전체 Finding: 3');
    expect(text).toContain('포함된 Finding: 1');
    expect(text).toContain('생략된 Finding: 2');
    expect(text).toContain('개별 검증 상태는 확인할 수 없습니다');
    const empty = createReviewMarkdown(context, scan({ finding_count: 0, displayed_finding_count: 0, findings: [], severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }));
    expect(empty).toContain('탐지 0건은 코드가 안전하다는 증명이 아닙니다.');
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
    const injected = createReviewMarkdown({ ...context, targetLabel: attack }, scan({ findings: [{ ...finding, file_path: `src/${attack}` }] }));
    expect(injected).not.toContain('<script>');
    expect(injected).not.toContain('\n[link]');
    expect(injected).not.toContain('![image]');
    expect(injected).toContain('&#x60;&#x60;&#x60;');
  });

  it('rejects context mismatch and output beyond the UTF-8 byte cap', () => {
    expect(() => createReviewMarkdown({ ...context, scanStatus: 'partial' }, scan())).toThrow('scan_context_mismatch');
    const huge = { ...finding, file_path: '가'.repeat(180_000) };
    expect(() => createReviewMarkdown(context, scan({ findings: [huge] }))).toThrow('export_size_limit_exceeded');
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
