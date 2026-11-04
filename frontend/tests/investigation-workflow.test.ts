import { describe, expect, it } from 'vitest';
import { validateInvestigationContext, type EvidenceBackedScan } from '../src/features/scans/investigationWorkflow';
import type { InvestigationEvaluation } from '../src/api/investigation';
import type { ScanSnapshot } from '../src/features/scans/compare';
import type { ScanResponse } from '../src/api/types';

const emptyScan: ScanResponse = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 0,
  displayed_finding_count: 0, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, issues: [], findings: [],
  limitations: ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'],
};
function evidence(scan: ScanResponse = emptyScan, runHandle = 'A'.repeat(43)): EvidenceBackedScan {
  return {
    snapshot: { scan, context: { targetId: 'project-a', targetLabel: 'Project A', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false, scanStatus: scan.scan_status, receivedAt: '2026-11-05T00:00:00.000Z' } } as ScanSnapshot,
    runHandle,
  };
}
const evaluation: InvestigationEvaluation = {
  contract_version: 'finding-disappearance-evaluation/v1', comparability: 'COMPARABLE', overall_assessment: 'UNDETERMINED', findings: [],
  limitation_codes: ['source_snapshot_not_collected'],
};

describe('investigation workflow binding', () => {
  it('accepts matching evidence-backed scans and zero-Finding evaluation', () => {
    const baseline = evidence();
    const current = evidence(emptyScan, 'B'.repeat(43));
    expect(validateInvestigationContext(baseline, current, evaluation)).toEqual({ valid: true });
  });

  it('rejects a v1 baseline with no server handle, identical run handles, or target/profile mismatch', () => {
    expect(validateInvestigationContext(null, evidence(), evaluation)).toEqual({ valid: false, reason: 'evidence_missing' });
    expect(validateInvestigationContext(evidence(), evidence(), evaluation)).toEqual({ valid: false, reason: 'same_run' });
    const other = evidence(emptyScan, 'B'.repeat(43)); other.snapshot.context = { ...other.snapshot.context, targetId: 'project-b' };
    expect(validateInvestigationContext(evidence(), other, evaluation)).toEqual({ valid: false, reason: 'context_mismatch' });
  });

  it('rejects server/client category or ID mismatch, duplicate IDs, and non-comparable local scans', () => {
    const id = `semgrep:${'a'.repeat(24)}`;
    const baselineScan = { ...emptyScan, finding_count: 1, displayed_finding_count: 1, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, findings: [{ finding_id: id } as ScanResponse['findings'][number]] };
    const currentScan = { ...emptyScan };
    const base = evidence(baselineScan, 'A'.repeat(43));
    const current = evidence(currentScan, 'B'.repeat(43));
    expect(validateInvestigationContext(base, current, { ...evaluation, findings: [{ finding_id: id, category: 'baselineOnly', path_observation: null, skip_hypothesis: null, source_snapshot_hypothesis: null, rule_identity_hypothesis: null }] })).toEqual({ valid: true });
    expect(validateInvestigationContext(base, current, { ...evaluation, findings: [{ finding_id: id, category: 'currentOnly', path_observation: null, skip_hypothesis: null, source_snapshot_hypothesis: null, rule_identity_hypothesis: null }] })).toEqual({ valid: false, reason: 'result_context_mismatch' });
    expect(validateInvestigationContext(base, current, { ...evaluation, findings: [{ finding_id: id, category: 'baselineOnly', path_observation: null, skip_hypothesis: null, source_snapshot_hypothesis: null, rule_identity_hypothesis: null }, { finding_id: id, category: 'baselineOnly', path_observation: null, skip_hypothesis: null, source_snapshot_hypothesis: null, rule_identity_hypothesis: null }] })).toEqual({ valid: false, reason: 'result_context_mismatch' });
  });
});
