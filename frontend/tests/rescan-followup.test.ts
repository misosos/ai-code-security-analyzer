import { describe, expect, it } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { compareScanSnapshots, type ScanSnapshot } from '../src/features/scans/compare';
import { createScanTriage } from '../src/features/scans/findingTriage';
import { createRescanFollowup } from '../src/features/scans/rescanFollowup';

const finding = (id: string, overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`,
  rule_id: `baseline.rule-${id}`,
  severity: 'high',
  verification_status: 'unverified',
  finding_kind: 'pattern',
  file_path: `src/${id}.js`,
  line_number: 7,
  evidence_validation_status: 'validated',
  supported_claims: ['match_reported'],
  restricted_claims: [],
  validation_error_code: null,
  ...overrides,
});

const scan = (findings: ApiFinding[], overrides: Partial<ScanResponse> = {}): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
  finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0,
  severity_counts: {
    critical: findings.filter((item) => item.severity === 'critical').length,
    high: findings.filter((item) => item.severity === 'high').length,
    medium: findings.filter((item) => item.severity === 'medium').length,
    low: findings.filter((item) => item.severity === 'low').length,
    info: findings.filter((item) => item.severity === 'info').length,
  },
  issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'], ...overrides,
});

const snapshot = (response: ScanResponse, context: Partial<ScanSnapshot['context']> = {}): ScanSnapshot => ({
  scan: response,
  context: {
    targetId: 'project-a', targetLabel: 'Project A', ruleProfileId: 'baseline',
    ruleProfileLabel: 'Baseline Rules', experimental: false, scanStatus: response.scan_status,
    receivedAt: '2026-11-03T00:00:00.000Z', ...context,
  },
});

describe('재검사 후속 검토 모델', () => {
  it('A,B에서 A,C로 바뀐 비교를 세 관찰 범주와 결정적인 작업으로 만든다', () => {
    const a = finding('1');
    const b = finding('2');
    const c = finding('3');
    const baseline = snapshot(scan([b, a]));
    const current = snapshot(scan([c, a]), { receivedAt: '2026-11-03T01:00:00.000Z' });
    const comparison = compareScanSnapshots(baseline, current);
    const triage = createScanTriage(current.scan);

    const left = createRescanFollowup(comparison, baseline, current, triage);
    const right = createRescanFollowup(comparison, baseline, current, triage);

    expect(left).toEqual(right);
    expect(left.comparable).toBe(true);
    expect(left.groups.currentOnly.map((item) => item.findingId)).toEqual([c.finding_id]);
    expect(left.groups.shared.map((item) => item.findingId)).toEqual([a.finding_id]);
    expect(left.groups.baselineOnly.map((item) => item.findingId)).toEqual([b.finding_id]);
    expect(left.groups.currentOnly[0].canOpenCurrentFinding).toBe(true);
    expect(left.groups.shared[0].triage?.recommendation).toBe('priority_code_review');
    expect(left.groups.baselineOnly[0].canOpenCurrentFinding).toBe(false);
    expect(left.groups.currentOnly[0].limitation).toContain('새로운 취약점이 발생했다는 증거가 아닙니다');
    expect(left.groups.baselineOnly[0].limitation).toContain('수정이나 해결 완료의 증거가 아닙니다');
  });

  it('공통 ID의 응답 메타데이터 차이만 나열하고 코드 동일성을 판단하지 않는다', () => {
    const before = finding('1', { line_number: 7, severity: 'medium', evidence_validation_status: 'rejected' });
    const after = finding('1', { line_number: 9, severity: 'high', evidence_validation_status: 'validated' });
    const baseline = snapshot(scan([before]));
    const current = snapshot(scan([after]), { receivedAt: '2026-11-03T01:00:00.000Z' });
    const result = createRescanFollowup(compareScanSnapshots(baseline, current), baseline, current, createScanTriage(current.scan));

    expect(result.groups.shared[0].changedMetadata).toEqual(['line_number', 'severity', 'evidence_validation_status']);
    expect(result.groups.shared[0].metadataSummary).toContain('응답 메타데이터');
    expect(result.groups.shared[0].metadataSummary).not.toMatch(/코드 (내용 )?(동일|변경 없음)/);
  });

  it('비교 가능한 메타데이터가 같아도 코드와 보안 상태 동일성을 주장하지 않는다', () => {
    const a = finding('1');
    const baseline = snapshot(scan([a]));
    const current = snapshot(scan([{ ...a }]), { receivedAt: '2026-11-03T01:00:00.000Z' });
    const result = createRescanFollowup(compareScanSnapshots(baseline, current), baseline, current, createScanTriage(current.scan));

    expect(result.groups.shared[0].changedMetadata).toEqual([]);
    expect(result.groups.shared[0].metadataSummary).toBe('비교 가능한 응답 메타데이터에서 차이가 관찰되지 않았습니다. 코드 내용이나 실제 보안 상태의 동일성을 뜻하지 않습니다.');
  });

  const blockedCases: Array<[string, (base: ScanSnapshot) => { comparison: ReturnType<typeof compareScanSnapshots>; current: ScanSnapshot | null }]> = [
    ['same snapshot', (base) => ({ comparison: compareScanSnapshots(base, base), current: base })],
    ['target mismatch', (base) => { const current = snapshot(scan([finding('2')]), { targetId: 'project-b' }); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['rule mismatch', (base) => { const current = snapshot(scan([finding('2')]), { ruleProfileId: 'other' }); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['version mismatch', (base) => { const current = snapshot(scan([finding('2')], { semgrep_version: '1.183.0' })); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['partial', (base) => { const current = snapshot(scan([finding('2')], { scan_status: 'partial', completed: false, limitations: ['scan_partial'] })); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['failed', (base) => { const current = snapshot(scan([], { scan_status: 'execution_failed', completed: false, limitations: ['scan_failed'] })); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['omitted', (base) => { const current = snapshot(scan([], { finding_count: 1, omitted_finding_count: 1, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, limitations: ['omitted_findings_not_individually_validated'] })); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['duplicate ID', (base) => { const duplicate = finding('2'); const current = snapshot(scan([duplicate, duplicate])); return { comparison: compareScanSnapshots(base, current), current }; }],
    ['current missing', (base) => ({ comparison: compareScanSnapshots(base, null), current: null })],
  ];

  it.each(blockedCases)('차단된 비교(%s)에서는 후속 검토 범주를 만들지 않는다', (_name, makeComparison) => {
    const baseline = snapshot(scan([finding('1')]));
    const { comparison, current } = makeComparison(baseline);
    const result = createRescanFollowup(comparison, baseline, current, current ? createScanTriage(current.scan) : null);
    expect(result.comparable).toBe(false);
    expect(result.groups).toEqual({ currentOnly: [], shared: [], baselineOnly: [] });
  });

  it('원본 Finding, 검사 응답, Triage를 변경하지 않는다', () => {
    const a = finding('1');
    const baseline = snapshot(scan([a]));
    const current = snapshot(scan([{ ...a }]), { receivedAt: '2026-11-03T01:00:00.000Z' });
    const triage = createScanTriage(current.scan);
    const before = JSON.stringify({ baseline, current, triage });
    createRescanFollowup(compareScanSnapshots(baseline, current), baseline, current, triage);
    expect(JSON.stringify({ baseline, current, triage })).toBe(before);
  });

  it('Finding 0건 비교도 빈 후속 검토 결과로 처리한다', () => {
    const baseline = snapshot(scan([]));
    const current = snapshot(scan([]), { receivedAt: '2026-11-03T01:00:00.000Z' });
    const result = createRescanFollowup(compareScanSnapshots(baseline, current), baseline, current, createScanTriage(current.scan));
    expect(result.comparable).toBe(true);
    expect(result.groups).toEqual({ currentOnly: [], shared: [], baselineOnly: [] });
  });
});
