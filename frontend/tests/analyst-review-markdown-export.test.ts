import { describe, expect, it, vi } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { emptyAnalystReviewState, setAnalystReviewNote, setAnalystReviewStatus } from '../src/features/scans/analystReview';
import { ANALYST_REVIEW_MARKDOWN_FILENAME, createAnalystReviewMarkdown, downloadAnalystReviewMarkdown, MAX_ANALYST_REVIEW_MARKDOWN_BYTES } from '../src/features/scans/analystReviewMarkdownExport';
import type { ScanContext } from '../src/features/scans/markdownExport';

const finding = (id: string, file = `src/${id}.ts`): ApiFinding => ({
  finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: `baseline.rule-${id}`, severity: 'high', verification_status: 'unverified',
  finding_kind: 'pattern', file_path: file, line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null,
});
const findings = [finding('a'), finding('b')];
const scan: ScanResponse = { scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 2, displayed_finding_count: 2, omitted_finding_count: 0, severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'] };
const context: ScanContext = { targetId: 'target-a', targetLabel: '합성 프로젝트', ruleProfileId: 'baseline', ruleProfileLabel: '기본 규칙', experimental: false, scanStatus: 'completed', receivedAt: '2026-10-31T02:00:00.000Z' };

describe('분석가 검토 Markdown 내보내기', () => {
  it('기본 검토 대기와 모든 Finding을 결정적인 순서로 내보내고 수동 상태를 보안 판정과 구분한다', () => {
    const first = createAnalystReviewMarkdown(context, scan, emptyAnalystReviewState, false);
    const reversed = createAnalystReviewMarkdown(context, { ...scan, findings: [...findings].reverse() }, emptyAnalystReviewState, false);
    expect(first).toBe(reversed);
    expect(first).toContain('검토 대기: 2');
    expect(first).toContain('Finding ID: semgrep:00000000000000000000000a');
    expect(first).toContain('수동 검토 상태: 검토 대기');
    expect(first).toContain('취약점 검증 상태: unverified');
    expect(first).toContain('근거 연결 검증 상태: validated');
    expect(first).toContain('검토 완료는 수정 완료나 취약점 해결을 의미하지 않습니다');
    expect(ANALYST_REVIEW_MARKDOWN_FILENAME).toBe('ai-code-security-analyst-review.md');
  });

  it('세 상태의 집계를 정확히 내보내고 메모는 기본 제외한다', () => {
    let state = setAnalystReviewStatus(emptyAnalystReviewState, findings, findings[0].finding_id, 'reviewed')!;
    state = setAnalystReviewStatus(state, findings, findings[1].finding_id, 'needs_followup')!;
    state = setAnalystReviewNote(state, findings, findings[0].finding_id, '내부 메모 <script>alert(1)</script>').state;
    const excluded = createAnalystReviewMarkdown(context, scan, state, false);
    expect(excluded).toContain('검토 대기: 0');
    expect(excluded).toContain('추가 확인 필요: 1');
    expect(excluded).toContain('검토 완료: 1');
    expect(excluded).not.toContain('내부 메모');
    const included = createAnalystReviewMarkdown(context, scan, state, true);
    expect(included).toContain('내부 메모 &#x3C;script&#x3E;');
    expect(included).not.toContain('<script>');
  });

  it('생략 항목 범위와 부분 검사 상태를 보고서에 명시한다', () => {
    const partialContext = { ...context, scanStatus: 'partial' as const };
    const partialScan = { ...scan, scan_status: 'partial' as const, completed: false, finding_count: 3, omitted_finding_count: 1, severity_counts: { ...scan.severity_counts, high: 3 } };
    const text = createAnalystReviewMarkdown(partialContext, partialScan, emptyAnalystReviewState, false);
    expect(text).toContain('부분 검사');
    expect(text).toContain('생략된 Finding: 1');
    expect(text).toContain('생략된 1개 Finding은 이 보고서와 검토 현황에 포함되지 않습니다');
    const failed = createAnalystReviewMarkdown({ ...context, scanStatus: 'timed_out' }, { ...scan, scan_status: 'timed_out', completed: false }, emptyAnalystReviewState, false);
    expect(failed).toContain('검사 상태: 시간 초과');
    expect(failed).toContain('검사가 정상 완료되지 않았습니다');
  });

  it('Finding 0건을 안전성 증명으로 표현하지 않고 입력 상태를 변경하지 않는다', () => {
    const emptyScan: ScanResponse = { ...scan, finding_count: 0, displayed_finding_count: 0, omitted_finding_count: 0, findings: [], severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } };
    const state = emptyAnalystReviewState;
    const before = [...state.entries()];
    const report = createAnalystReviewMarkdown(context, emptyScan, state, true);
    expect(report).toContain('현재 API 응답에 포함된 Finding이 없습니다');
    expect(report).toContain('검토 완료: 0');
    expect(report).toContain('탐지 0건은 프로젝트 안전성의 증명이 아닙니다');
    expect([...state.entries()]).toEqual(before);
  });

  it('다른 검사 문맥, 잘못된 기록, 경로 및 초과 크기는 실패 처리한다', () => {
    expect(() => createAnalystReviewMarkdown({ ...context, targetId: '../other' }, scan, emptyAnalystReviewState, false)).toThrow('scan_context_invalid');
    expect(() => createAnalystReviewMarkdown({ ...context, targetLabel: '/private/project' }, scan, emptyAnalystReviewState, false)).toThrow('scan_context_invalid');
    expect(() => createAnalystReviewMarkdown({ ...context, scanStatus: 'partial' }, scan, emptyAnalystReviewState, false)).toThrow('scan_context_mismatch');
    const extra = new Map([['semgrep:ffffffffffffffffffffffff', { status: 'reviewed', note: '' }]]) as never;
    expect(() => createAnalystReviewMarkdown(context, scan, extra, false)).toThrow('review_state_invalid');
    const oversized = new Map([[findings[0].finding_id, { status: 'reviewed', note: '가'.repeat(683) }]]) as never;
    expect(() => createAnalystReviewMarkdown(context, scan, oversized, true)).toThrow('review_state_invalid');
    const invalidStatus = new Map([[findings[0].finding_id, { status: 'confirmed_fixed', note: '' }]]) as never;
    expect(() => createAnalystReviewMarkdown(context, scan, invalidStatus, false)).toThrow('review_state_invalid');
    expect(() => createAnalystReviewMarkdown(context, { ...scan, findings: [{ ...findings[0], file_path: '/private/project.ts' }, findings[1]] }, emptyAnalystReviewState, false)).toThrow('scan_response_invalid');
    const huge = { ...findings[0], file_path: `src/${'가'.repeat(180_000)}.ts` };
    expect(() => createAnalystReviewMarkdown(context, { ...scan, findings: [huge], finding_count: 1, displayed_finding_count: 1, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } }, emptyAnalystReviewState, false)).toThrow('analyst_review_export_size_limit_exceeded');
    expect(MAX_ANALYST_REVIEW_MARKDOWN_BYTES).toBe(512 * 1024);
  });

  it('토큰·원문 코드·절대 경로를 포함하지 않고 API 경로 문법을 이스케이프한다', () => {
    const state = setAnalystReviewNote(emptyAnalystReviewState, findings, findings[0].finding_id, 'sensitive-note-token\u202e\u001b').state;
    const text = createAnalystReviewMarkdown(context, { ...scan, findings: [{ ...findings[0], file_path: 'src/<script>.ts' }, findings[1]] }, state, true);
    expect(text).not.toContain('synthetic-review-token');
    expect(text).not.toContain('/Users/');
    expect(text).not.toContain('<script>');
    expect(text).toContain('src/&#x3C;script&#x3E;.ts');
    expect(text).toContain('&#x202E;&#x1B;');
    expect(text).not.toContain('source code');
  });

  it('고정 파일명으로 다운로드하고 크기 초과는 파일 생성 전에 거부한다', () => {
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:analyst-report');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    vi.useFakeTimers();
    downloadAnalystReviewMarkdown('# report');
    expect(create).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(document.querySelector('a[download]')).toBeNull();
    expect(() => downloadAnalystReviewMarkdown('x'.repeat(MAX_ANALYST_REVIEW_MARKDOWN_BYTES + 1))).toThrow('analyst_review_export_size_limit_exceeded');
    expect(create).toHaveBeenCalledOnce();
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:analyst-report');
    vi.useRealTimers();
  });
});
