import { describe, expect, it } from 'vitest';
import { canInvestigateBlockedPartialComparison, validateInvestigationContext, type EvidenceBackedScan } from '../src/features/scans/investigationWorkflow';
import { compareScanSnapshots } from '../src/features/scans/compare';
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

  it('allows a bound partial investigation evaluation while the ordinary comparator stays blocked', () => {
    const id = `semgrep:${'b'.repeat(24)}`;
    const baselineScan = { ...emptyScan, finding_count: 1, displayed_finding_count: 1,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      findings: [{ finding_id: id } as ScanResponse['findings'][number]] };
    const partialScan: ScanResponse = { ...emptyScan, scan_status: 'partial', completed: false,
      issues: ['semgrep_skipped_paths'], limitations: [...emptyScan.limitations, 'scan_partial'] };
    const baseline = evidence(baselineScan, 'A'.repeat(43));
    const current = evidence(partialScan, 'B'.repeat(43));
    const comparison = compareScanSnapshots(baseline.snapshot, current.snapshot);
    expect(comparison.comparable).toBe(false);
    expect(comparison.reasons).toEqual(['current_not_completed']);
    expect(canInvestigateBlockedPartialComparison(baseline, current, comparison)).toBe(true);
    const partialEvaluation: InvestigationEvaluation = {
      ...evaluation, comparability: 'INCOMPARABLE', overall_assessment: 'INCOMPARABLE',
      findings: [{ finding_id: id, category: 'baselineOnly', path_observation: 'PATH_EXPLICITLY_SKIPPED',
        skip_hypothesis: 'SUPPORTED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' }],
      limitation_codes: ['scan_incomplete', 'source_snapshot_not_collected'],
    };
    expect(validateInvestigationContext(baseline, current, partialEvaluation, comparison)).toEqual({ valid: true });
    expect(validateInvestigationContext(baseline, current, { ...partialEvaluation, overall_assessment: 'EXPLANATION_SUPPORTED' }, comparison))
      .toEqual({ valid: false, reason: 'result_context_mismatch' });
  });

  it('rejects partial investigations when comparator has an unrelated blocker or no matching run evidence', () => {
    const partial: ScanResponse = { ...emptyScan, scan_status: 'partial', completed: false,
      issues: ['semgrep_skipped_paths'], limitations: [...emptyScan.limitations, 'scan_partial'] };
    const baseline = evidence(emptyScan, 'A'.repeat(43));
    const current = evidence({ ...partial, semgrep_version: '1.182.0' }, 'B'.repeat(43));
    const comparison = compareScanSnapshots(baseline.snapshot, current.snapshot);
    expect(comparison.reasons).toEqual(['current_not_completed', 'semgrep_version_mismatch']);
    expect(canInvestigateBlockedPartialComparison(baseline, current, comparison)).toBe(false);
    expect(canInvestigateBlockedPartialComparison(null, current, comparison)).toBe(false);
    expect(canInvestigateBlockedPartialComparison(baseline, { ...current, runHandle: baseline.runHandle }, comparison)).toBe(false);
  });
});
