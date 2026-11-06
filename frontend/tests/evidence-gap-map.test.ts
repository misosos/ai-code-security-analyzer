import { describe, expect, it } from 'vitest';
import { createEvidenceGapMap, type GapStatus } from '../src/features/scans/evidenceGapMap';
import { compareScanSnapshots } from '../src/features/scans/compare';
import type { EvidenceBackedScan } from '../src/features/scans/investigationWorkflow';
import type { InvestigationEvaluation, InvestigationPathObservation, RuleBytesComparison } from '../src/api/investigation';
import type { ApiFinding, ScanResponse } from '../src/api/types';
const id = `semgrep:${'b'.repeat(24)}`;
const finding = { finding_id: id, rule_id: 'baseline.test', file_path: 'retired.js' } as ApiFinding;
const scan = (findings: ApiFinding[], partial = false): ScanResponse => ({ scan_status: partial ? 'partial' : 'completed', completed: !partial, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: [] });
const evidence = (value: ScanResponse, handle: string, mode: 'standard' | 'rule-bytes' = 'standard'): EvidenceBackedScan => ({ runHandle: handle.repeat(43), evidenceMode: mode, snapshot: { scan: value, context: { targetId: 'project', targetLabel: 'Project', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false, scanStatus: value.scan_status, receivedAt: '2026-01-01T00:00:00Z' } } });
const evaluation = (path: InvestigationPathObservation | null = 'PATH_EXPLICITLY_SKIPPED', partial = false): InvestigationEvaluation => ({ contract_version: 'finding-disappearance-evaluation/v1', comparability: partial ? 'INCOMPARABLE' : 'COMPARABLE', overall_assessment: partial ? 'INCOMPARABLE' : 'UNDETERMINED', findings: [{ finding_id: id, category: 'baselineOnly', path_observation: path, skip_hypothesis: path === 'PATH_EXPLICITLY_SKIPPED' ? 'SUPPORTED' : path === 'PATH_REPORTED_SCANNED' ? 'CONTRADICTED' : path === 'CONFLICTING' ? 'INCOMPARABLE' : 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' }], limitation_codes: ['source_snapshot_not_collected', 'loaded_rule_identity_unverified', 'scope_completeness_unverified', 'rule_bytes_unverified', ...(partial ? ['scan_incomplete' as const] : [])] });
const rule = (status: RuleBytesComparison['status']): RuleBytesComparison => ({ contract_version: 'rule-bytes-comparison/v1', status, limitation_codes: ['selected_rule_bytes_only', 'loaded_rule_identity_unverified'] });
const project = (a: EvidenceBackedScan, b: EvidenceBackedScan, result: unknown, bytes: unknown | null = null) => createEvidenceGapMap(a, b, result, bytes, compareScanSnapshots(a.snapshot, b.snapshot));
describe('security evidence gap projection', () => {
  it('is deterministic and separates skipped findings from run-wide limits', () => {
    const a = evidence(scan([finding]), 'A'); const b = evidence(scan([], true), 'B');
    const map = project(a, b, evaluation('PATH_EXPLICITLY_SKIPPED', true));
    expect(map).toEqual(project(a, b, evaluation('PATH_EXPLICITLY_SKIPPED', true)));
    expect(map?.findings[0].pathEvidence.status).toBe('OBSERVED');
    expect(map?.entries.find((x) => x.id === 'comparison')?.status).toBe('INCOMPARABLE');
    expect(map?.entries.find((x) => x.id === 'source')?.status).toBe('NOT_COLLECTED');
    expect(map?.entries.find((x) => x.id === 'loaded-rules')?.status).toBe('UNVERIFIED');
    expect(map?.entries.find((x) => x.id === 'scope')?.status).toBe('UNVERIFIED');
    expect(map?.entries.find((x) => x.id === 'rule-bytes')?.fact).toContain('요청하지 않았습니다');
    expect(map?.actions[0]).toContain('검사 상태');
    expect(JSON.stringify(map)).not.toContain('.semgrepignore');
  });
  it.each<[InvestigationPathObservation, GapStatus]>([['PATH_REPORTED_SCANNED', 'OBSERVED'], ['PATH_EXPLICITLY_SKIPPED', 'OBSERVED'], ['PATH_NOT_REPORTED', 'NOT_REPORTED'], ['SKIP_EVIDENCE_NOT_COLLECTED', 'NOT_COLLECTED'], ['SCOPE_EVIDENCE_UNAVAILABLE', 'UNAVAILABLE'], ['FINDING_PATH_UNAVAILABLE', 'UNAVAILABLE'], ['CONFLICTING', 'CONFLICTING']])('preserves path observation %s', (path, status) => {
    expect(project(evidence(scan([finding]), 'A'), evidence(scan([]), 'B'), evaluation(path))?.findings[0].pathEvidence.status).toBe(status);
  });
  it.each(['SAME_SELECTED_BYTES', 'DIFFERENT_SELECTED_BYTES', 'UNVERIFIED', 'INCOMPARABLE'] as const)('maps rule state %s', (status) => {
    const map = project(evidence(scan([finding]), 'A', 'rule-bytes'), evidence(scan([]), 'B', 'rule-bytes'), evaluation(), rule(status));
    expect(map?.entries.find((x) => x.id === 'rule-bytes')?.status).toBe(status === 'SAME_SELECTED_BYTES' || status === 'DIFFERENT_SELECTED_BYTES' ? 'OBSERVED' : status);
    expect(map?.entries.find((x) => x.id === 'loaded-rules')?.status).toBe('UNVERIFIED');
  });
  it('rejects missing, malformed, mismatched, duplicate, mixed and partial equality evidence', () => {
    const a = evidence(scan([finding]), 'A', 'rule-bytes'); const b = evidence(scan([]), 'B', 'rule-bytes');
    expect(project(a, b, evaluation(), null)).toBeNull();
    expect(project({ ...a, validUntilMs: -1 }, b, evaluation(), rule('UNVERIFIED'))).toBeNull();
    expect(project({ ...a, validUntilWallMs: 1 }, b, evaluation(), rule('UNVERIFIED'))).toBeNull();
    expect(project(a, b, evaluation(), { ...rule('UNVERIFIED'), contract_version: 'bad' })).toBeNull();
    expect(project(a, b, { ...evaluation(), findings: [{ ...evaluation().findings[0], category: 'currentOnly' }] }, rule('UNVERIFIED'))).toBeNull();
    expect(project(a, b, { ...evaluation('PATH_NOT_REPORTED'), findings: [{ ...evaluation('PATH_NOT_REPORTED').findings[0], skip_hypothesis: 'SUPPORTED' }] }, rule('UNVERIFIED'))).toBeNull();
    expect(project(a, { ...b, evidenceMode: 'standard' }, evaluation(), rule('UNVERIFIED'))).toBeNull();
    expect(project(evidence(scan([finding, finding]), 'C', 'rule-bytes'), b, evaluation(), rule('UNVERIFIED'))).toBeNull();
    expect(project(a, evidence(scan([], true), 'B', 'rule-bytes'), evaluation('PATH_EXPLICITLY_SKIPPED', true), rule('SAME_SELECTED_BYTES'))).toBeNull();
  });
  it('handles zero findings without a fabricated per-Finding observation', () => {
    const map = project(evidence(scan([]), 'A'), evidence(scan([]), 'B'), { ...evaluation(), findings: [] });
    expect(map?.findings).toEqual([]);
    expect(map?.entries.find((x) => x.id === 'resolution')?.fact).toContain('판정할 수 없습니다');
    expect(project(evidence(scan([]), 'A'), evidence(scan([]), 'B'), { ...evaluation(), findings: [], overall_assessment: 'MULTIPLE_EXPLANATIONS_POSSIBLE' })).not.toBeNull();
  });
});
