import { describe, expect, it } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import type { ScanContext } from '../src/features/scans/markdownExport';
import { compareScanSnapshots, type ScanSnapshot } from '../src/features/scans/compare';

const finding = (id: string, overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: `semgrep:${Array.from(id, (char) => char.codePointAt(0)!.toString(16)).join('').padStart(24, '0').slice(-24)}`,
  rule_id: 'baseline.sample-rule', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern',
  file_path: 'src/sample.js', line_number: 12, evidence_validation_status: 'validated',
  supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null, ...overrides,
});

const scan = (findings: ApiFinding[] = []): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length,
  displayed_finding_count: findings.length, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
  issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'],
});

const context = (overrides: Partial<ScanContext> = {}): ScanContext => ({
  targetId: 'project-a', targetLabel: 'Project A', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline',
  experimental: false, scanStatus: 'completed', receivedAt: '2026-10-31T01:00:00.000Z', ...overrides,
});

const snapshot = (findings: ApiFinding[] = [], scanOverrides: Partial<ScanResponse> = {}, contextOverrides: Partial<ScanContext> = {}): ScanSnapshot => ({
  scan: { ...scan(findings), ...scanOverrides }, context: context(contextOverrides),
});

describe('보수적인 검사 결과 비교', () => {
  it('정확히 일치하는 Finding ID를 공통으로, 나머지를 각 검사 단독 항목으로 분류한다', () => {
    const shared = finding('1');
    const baselineOnly = finding('2');
    const currentOnly = finding('3');
    const result = compareScanSnapshots(snapshot([shared, baselineOnly]), snapshot([currentOnly, shared]));
    expect(result.comparable).toBe(true);
    expect(result.groups).toEqual({ currentOnly: [currentOnly], shared: [shared], baselineOnly: [baselineOnly] });
  });

  it('입력 순서가 달라도 범주별 순서를 Finding ID로 고정한다', () => {
    const a = finding('1'); const b = finding('2'); const c = finding('3');
    const left = compareScanSnapshots(snapshot([a, b]), snapshot([c, a]));
    const right = compareScanSnapshots(snapshot([b, a]), snapshot([a, c]));
    expect(right).toEqual(left);
  });

  it('두 결과가 모두 0건이면 비교 가능한 빈 범주를 반환한다', () => {
    const result = compareScanSnapshots(snapshot(), snapshot());
    expect(result).toEqual({ comparable: true, reasons: [], groups: { currentOnly: [], shared: [], baselineOnly: [] } });
  });

  it('현재 검사를 기준으로 지정한 직후에는 재검사 전까지 비교를 보류한다', () => {
    const same = snapshot([finding('1')]);
    expect(compareScanSnapshots(same, same).reasons).toContain('same_scan_snapshot');
  });

  it.each([
    ['다른 프로젝트', snapshot([], {}, { targetId: 'project-a' }), snapshot([], {}, { targetId: 'project-b' }), 'target_mismatch'],
    ['다른 규칙 프로필', snapshot([], {}, { ruleProfileId: 'baseline' }), snapshot([], {}, { ruleProfileId: 'strict' }), 'rule_profile_mismatch'],
    ['Experimental 상태 변경', snapshot([], {}, { experimental: false }), snapshot([], {}, { experimental: true }), 'rule_profile_mismatch'],
    ['Semgrep 버전 변경', snapshot([], { semgrep_version: '1.182.1' }), snapshot([], { semgrep_version: '1.183.0' }), 'semgrep_version_mismatch'],
    ['버전 확인 불가', snapshot([], { semgrep_version: null }), snapshot([], { semgrep_version: '1.182.1' }), 'semgrep_version_unavailable'],
    ['부분 검사', snapshot(), snapshot([], { scan_status: 'partial', completed: false }, { scanStatus: 'partial' }), 'current_not_completed'],
    ['실패 검사', snapshot([], { scan_status: 'execution_failed', completed: false }, { scanStatus: 'execution_failed' }), snapshot(), 'baseline_not_completed'],
    ['현재 응답에서 생략된 Finding', snapshot(), snapshot([], { finding_count: 2, displayed_finding_count: 0, omitted_finding_count: 2, severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 } }), 'current_findings_omitted'],
    ['수신 시점 문맥 불일치', snapshot([], {}, { scanStatus: 'partial' }), snapshot(), 'baseline_context_mismatch'],
  ] as const)('%s이면 개별 Finding 비교를 차단한다', (_label, baseline, current, reason) => {
    const result = compareScanSnapshots(baseline, current);
    expect(result.comparable).toBe(false);
    expect(result.groups).toBeNull();
    expect(result.reasons).toContain(reason);
  });

  it('Finding ID가 위치 변경으로 달라지면 단독 관찰로 남기고 해결/신규 판정을 만들지 않는다', () => {
    const before = finding('1', { file_path: 'src/sample.js', line_number: 12 });
    const after = finding('2', { file_path: 'src/sample.js', line_number: 13 });
    const result = compareScanSnapshots(snapshot([before]), snapshot([after]));
    expect(result.comparable).toBe(true);
    expect(result.groups?.currentOnly).toEqual([after]);
    expect(result.groups?.baselineOnly).toEqual([before]);
    expect(JSON.stringify(result)).not.toMatch(/취약점 해결|수정 완료|새 취약점/);
  });

  it('중복 Finding ID 또는 요약 수 불일치는 비교를 차단한다', () => {
    const duplicate = finding('1');
    const duplicateResult = compareScanSnapshots(snapshot([duplicate, duplicate]), snapshot());
    const inconsistentResult = compareScanSnapshots(snapshot(), snapshot([], { finding_count: 2 }));
    expect(duplicateResult.reasons).toContain('baseline_duplicate_finding_id');
    expect(inconsistentResult.reasons).toContain('current_count_inconsistent');
  });

  it('기준 또는 현재 검사가 없으면 비교할 수 없다', () => {
    expect(compareScanSnapshots(null, snapshot()).reasons).toContain('baseline_missing');
    expect(compareScanSnapshots(snapshot(), null).reasons).toContain('current_missing');
  });
});
