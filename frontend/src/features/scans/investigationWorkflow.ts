import type { InvestigationEvaluation } from '../../api/investigation';
import type { ScanComparison, ScanSnapshot } from './compare';

/** A validated scan response and the opaque handle issued for that exact response. */
export interface EvidenceBackedScan {
  readonly snapshot: ScanSnapshot;
  readonly runHandle: string;
}

export type InvestigationBindingFailure = 'evidence_missing' | 'same_run' | 'context_mismatch' | 'result_context_mismatch' | 'comparison_unavailable';
export type InvestigationBindingResult = { valid: true } | { valid: false; reason: InvestigationBindingFailure };

export function validateInvestigationRuns(
  baseline: EvidenceBackedScan | null,
  current: EvidenceBackedScan | null,
): InvestigationBindingResult {
  if (!baseline || !current) return { valid: false, reason: 'evidence_missing' };
  if (baseline.runHandle === current.runHandle) return { valid: false, reason: 'same_run' };
  const base = baseline.snapshot;
  const now = current.snapshot;
  if (base.context.targetId !== now.context.targetId || base.context.ruleProfileId !== now.context.ruleProfileId
    || base.context.experimental !== now.context.experimental) return { valid: false, reason: 'context_mismatch' };
  return { valid: true };
}

/** A blocked browser comparison may be bypassed only for a well-formed partial scan pair. */
export function canInvestigateBlockedPartialComparison(
  baseline: EvidenceBackedScan | null,
  current: EvidenceBackedScan | null,
  comparison: ScanComparison,
): boolean {
  if (comparison.comparable || !comparison.reasons.length) return comparison.comparable;
  if (!validateInvestigationRuns(baseline, current).valid || !baseline || !current) return false;
  const snapshots = [baseline.snapshot, current.snapshot];
  if (snapshots.some(({ scan, context }) =>
    !['completed', 'partial'].includes(scan.scan_status)
    || scan.completed !== (scan.scan_status === 'completed')
    || context.scanStatus !== scan.scan_status
    || scan.omitted_finding_count !== 0
    || scan.finding_count !== scan.displayed_finding_count
    || scan.displayed_finding_count !== scan.findings.length
    || new Set(scan.findings.map((item) => item.finding_id)).size !== scan.findings.length)) return false;
  const expectedReasons = snapshots.flatMap(({ scan }, index) => scan.scan_status === 'partial'
    ? [index === 0 ? 'baseline_not_completed' : 'current_not_completed'] : []);
  return expectedReasons.length > 0
    && comparison.reasons.length === expectedReasons.length
    && expectedReasons.every((reason) => comparison.reasons.includes(reason as typeof comparison.reasons[number]));
}

/** Require the server result to describe exactly the ID/category partition already shown by the client comparator. */
export function validateInvestigationContext(
  baseline: EvidenceBackedScan | null,
  current: EvidenceBackedScan | null,
  evaluation: InvestigationEvaluation,
  comparison?: ScanComparison,
): InvestigationBindingResult {
  const runsValid = validateInvestigationRuns(baseline, current);
  if (!runsValid.valid) return runsValid;
  if (!baseline || !current) return { valid: false, reason: 'evidence_missing' };
  const base = baseline.snapshot;
  const now = current.snapshot;
  if (comparison && (!comparison.comparable || !comparison.groups)
    && !canInvestigateBlockedPartialComparison(baseline, current, comparison)) {
    return { valid: false, reason: 'comparison_unavailable' };
  }

  const expected = new Map<string, string>();
  if (comparison?.groups) {
    for (const [category, findings] of Object.entries(comparison.groups)) {
      for (const finding of findings) expected.set(finding.finding_id, category);
    }
  } else {
    const baselineIds = new Set(base.scan.findings.map((finding) => finding.finding_id));
    const currentIds = new Set(now.scan.findings.map((finding) => finding.finding_id));
    for (const id of currentIds) expected.set(id, baselineIds.has(id) ? 'shared' : 'currentOnly');
    for (const id of baselineIds) if (!currentIds.has(id)) expected.set(id, 'baselineOnly');
  }

  if (evaluation.findings.length !== expected.size) return { valid: false, reason: 'result_context_mismatch' };
  const hasPartialRun = base.scan.scan_status === 'partial' || now.scan.scan_status === 'partial';
  if (hasPartialRun && (evaluation.comparability !== 'INCOMPARABLE'
    || evaluation.overall_assessment !== 'INCOMPARABLE'
    || !evaluation.limitation_codes.includes('scan_incomplete'))) {
    return { valid: false, reason: 'result_context_mismatch' };
  }
  const actual = new Map(evaluation.findings.map((item) => [item.finding_id, item.category]));
  if (actual.size !== expected.size) return { valid: false, reason: 'result_context_mismatch' };
  for (const [id, category] of expected) if (actual.get(id) !== category) return { valid: false, reason: 'result_context_mismatch' };
  return { valid: true };
}
