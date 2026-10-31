import { describe, expect, it, vi } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { compareScanSnapshots, type ScanSnapshot } from '../src/features/scans/compare';
import { createComparisonMarkdown, downloadComparisonMarkdown, MAX_COMPARISON_MARKDOWN_BYTES, COMPARISON_MARKDOWN_FILENAME } from '../src/features/scans/comparisonMarkdownExport';

const finding = (id: string, overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: `semgrep:${id.padStart(24, '0')}`, rule_id: `rules.${id}`, severity: 'high', verification_status: 'unverified',
  finding_kind: 'pattern', file_path: `src/${id}.py`, line_number: 12, evidence_validation_status: 'validated',
  supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null, ...overrides,
});
const scan = (findings: ApiFinding[] = []): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length,
  displayed_finding_count: findings.length, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
  issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'],
});
const snapshot = (findings: ApiFinding[] = [], overrides: Partial<ScanResponse> = {}, contextOverrides: Partial<ScanSnapshot['context']> = {}): ScanSnapshot => ({
  scan: { ...scan(findings), ...overrides },
  context: { targetId: 'project-a', targetLabel: 'Project A', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false, scanStatus: 'completed', receivedAt: '2026-11-01T01:00:00.000Z', ...contextOverrides },
});

describe('검사 비교 Markdown 보고서', () => {
  it('비교 문맥과 3개 범주의 전체 Finding 및 근거 메타데이터를 출력한다', () => {
    const commonBefore = finding('01', { severity: 'medium', file_path: 'src/before.py', line_number: 5 });
    const commonAfter = finding('01', { severity: 'high', file_path: 'src/after.py', line_number: 8, evidence_validation_status: 'unavailable', supported_claims: [], restricted_claims: [] });
    const currentOnly = finding('02');
    const baselineOnly = finding('03');
    const report = createComparisonMarkdown(
      snapshot([commonBefore, baselineOnly], {}, { receivedAt: '2026-11-01T00:00:00.000Z' }),
      snapshot([currentOnly, commonAfter], {}, { receivedAt: '2026-11-01T01:00:00.000Z' }),
    );
    expect(report).toContain('기준 검사 대상: Project A (project-a)');
    expect(report).toContain('기준 결과 수신 시각 (브라우저 기록, ISO 8601)');
    expect(report).toContain('이번 검사에서만 관찰: 1');
    expect(report).toContain('양쪽에서 관찰: 1');
    expect(report).toContain('기준 검사에서만 관찰: 1');
    for (const item of ['semgrep:'.concat('0'.repeat(22), '01'), 'semgrep:'.concat('0'.repeat(22), '02'), 'semgrep:'.concat('0'.repeat(22), '03')]) expect(report).toContain(item);
    expect(report).toContain('src/before.py:5');
    expect(report).toContain('src/after.py:8');
    expect(report).toContain('근거 연결 상태: unavailable');
    expect(report).toContain('규칙 매치 보고 (match&#x5F;reported)');
    expect(report).toContain('independent&#x5F;confirmation&#x5F;required');
    expect(report).toContain('실제 취약점의 발생·해결');
    expect(report).toContain('CLI의 정식 보안 검토 보고서를 대체하지 않습니다');
  });

  it('두 Finding이 모두 0개인 비교 보고서를 생성한다', () => {
    const report = createComparisonMarkdown(snapshot(), snapshot([], {}, { receivedAt: '2026-11-01T02:00:00.000Z' }));
    expect(report).toContain('기준 검사 Finding 총수: 0');
    expect(report).toContain('현재 검사 Finding 총수: 0');
    expect(report).toContain('해당하는 Finding이 없습니다.');
  });

  it('Finding 순서와 무관하게 결정적인 보고서를 생성한다', () => {
    const a = finding('01'); const b = finding('02'); const c = finding('03');
    const left = createComparisonMarkdown(snapshot([a, b]), snapshot([c, a], {}, { receivedAt: '2026-11-01T02:00:00.000Z' }));
    const right = createComparisonMarkdown(snapshot([b, a]), snapshot([a, c], {}, { receivedAt: '2026-11-01T02:00:00.000Z' }));
    expect(right).toBe(left);
  });

  it.each([
    ['다른 대상', snapshot([], {}, { targetId: 'a' }), snapshot([], {}, { targetId: 'b' })],
    ['다른 규칙', snapshot([], {}, { ruleProfileId: 'a' }), snapshot([], {}, { ruleProfileId: 'b' })],
    ['Semgrep 버전 불일치', snapshot([], { semgrep_version: '1.182.1' }), snapshot([], { semgrep_version: '1.183.0' })],
    ['부분 검사', snapshot(), snapshot([], { scan_status: 'partial', completed: false }, { scanStatus: 'partial' })],
    ['실패 검사', snapshot([], { scan_status: 'execution_failed', completed: false }, { scanStatus: 'execution_failed' }), snapshot()],
    ['생략된 Finding', snapshot(), snapshot([], { finding_count: 1, displayed_finding_count: 0, omitted_finding_count: 1, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } })],
  ])('%s 비교는 보고서 생성이 차단된다', (_label, baseline, current) => {
    expect(() => createComparisonMarkdown(baseline, current)).toThrow('comparison_not_exportable');
  });

  it('동일한 snapshot 재사용을 차단한다', () => {
    const same = snapshot([finding('01')]);
    expect(() => createComparisonMarkdown(same, same)).toThrow('comparison_not_exportable');
  });

  it('Markdown/HTML 구분자와 제어 문자를 안전하게 인코딩하고 절대 경로를 제외한다', () => {
    const hostile = finding('01', { file_path: 'src/<img src=x onerror=alert(1)>\u202E[click](https:bad.test).py\u0000' });
    const report = createComparisonMarkdown(snapshot(), snapshot([hostile]));
    expect(report).toContain('&#x3C;img');
    expect(report).not.toContain('<img');
    expect(report).toContain('onerror=alert');
    expect(report).toContain('&#x202E;');
    expect(report).toContain('&#x0;');
    expect(report).not.toContain('](https:bad.test)');
    const absolute = finding('02', { file_path: '/Users/private/project/file.py' });
    const absoluteReport = createComparisonMarkdown(snapshot(), snapshot([absolute]));
    expect(absoluteReport).not.toContain('/Users/private');
    expect(absoluteReport).toContain('절대 경로는 보고서에서 제외');
  });

  it('UTF-8 512 KiB를 초과하면 결과 전체를 거부하고 다운로드를 시도하지 않는다', () => {
    const tooLarge = snapshot([finding('01', { file_path: `src/${'가'.repeat(MAX_COMPARISON_MARKDOWN_BYTES)}.py` })]);
    const download = vi.spyOn(URL, 'createObjectURL');
    expect(() => createComparisonMarkdown(snapshot(), tooLarge)).toThrow('comparison_export_size_limit_exceeded');
    expect(() => downloadComparisonMarkdown('x'.repeat(MAX_COMPARISON_MARKDOWN_BYTES + 1))).toThrow('comparison_export_size_limit_exceeded');
    expect(download).not.toHaveBeenCalled();
  });

  it('다운로드 시 고정 파일명과 임시 Blob URL을 사용하고 URL을 정리한다', () => {
    vi.useFakeTimers();
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:comparison-report');
    const revoke = vi.spyOn(URL, 'revokeObjectURL');
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    downloadComparisonMarkdown('# report');
    const anchor = document.querySelector<HTMLAnchorElement>('a[download]');
    expect(anchor).toBeNull();
    expect(create).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(COMPARISON_MARKDOWN_FILENAME).toBe('ai-code-security-comparison.md');
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:comparison-report');
    vi.useRealTimers();
  });

  it('순수 보고서 생성은 비교 함수를 재검증하며 UI에서 전달된 임의 그룹을 받지 않는다', () => {
    const baseline = snapshot(); const current = baseline;
    expect(compareScanSnapshots(baseline, current).comparable).toBe(false);
    expect(() => createComparisonMarkdown(baseline, current)).toThrow('comparison_not_exportable');
  });
});
