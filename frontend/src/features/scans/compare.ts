import type { ApiFinding, ScanResponse } from '../../api/types';
import type { ScanContext } from './markdownExport';

export interface ScanSnapshot {
  /** API-validated response returned by parseScan. */
  scan: ScanResponse;
  /** Immutable request context captured when that response arrived. */
  context: ScanContext;
}

export type ComparisonBlockReason =
  | 'baseline_missing' | 'current_missing'
  | 'same_scan_snapshot'
  | 'baseline_not_completed' | 'current_not_completed'
  | 'baseline_findings_omitted' | 'current_findings_omitted'
  | 'target_mismatch' | 'rule_profile_mismatch'
  | 'semgrep_version_unavailable' | 'semgrep_version_mismatch'
  | 'baseline_context_mismatch' | 'current_context_mismatch'
  | 'baseline_duplicate_finding_id' | 'current_duplicate_finding_id'
  | 'baseline_count_inconsistent' | 'current_count_inconsistent';

export interface ComparisonGroups {
  currentOnly: ApiFinding[];
  shared: ApiFinding[];
  baselineOnly: ApiFinding[];
}

export interface ScanComparison {
  comparable: boolean;
  reasons: ComparisonBlockReason[];
  groups: ComparisonGroups | null;
}

function hasDuplicateIds(findings: ApiFinding[]): boolean {
  return new Set(findings.map((finding) => finding.finding_id)).size !== findings.length;
}

function hasConsistentCounts(scan: ScanResponse): boolean {
  return scan.finding_count === scan.displayed_finding_count + scan.omitted_finding_count
    && scan.displayed_finding_count === scan.findings.length;
}

/**
 * Compare only API-validated, complete responses with matching scan context.
 * Finding ID equality means the same reported location ID, not semantic identity.
 */
export function compareScanSnapshots(baseline: ScanSnapshot | null, current: ScanSnapshot | null): ScanComparison {
  const reasons: ComparisonBlockReason[] = [];
  if (!baseline) reasons.push('baseline_missing');
  if (!current) reasons.push('current_missing');

  if (baseline) {
    if (baseline.scan.scan_status !== 'completed' || !baseline.scan.completed) reasons.push('baseline_not_completed');
    if (baseline.scan.omitted_finding_count !== 0) reasons.push('baseline_findings_omitted');
    if (baseline.context.scanStatus !== baseline.scan.scan_status) reasons.push('baseline_context_mismatch');
    if (hasDuplicateIds(baseline.scan.findings)) reasons.push('baseline_duplicate_finding_id');
    if (!hasConsistentCounts(baseline.scan)) reasons.push('baseline_count_inconsistent');
  }
  if (current) {
    if (current.scan.scan_status !== 'completed' || !current.scan.completed) reasons.push('current_not_completed');
    if (current.scan.omitted_finding_count !== 0) reasons.push('current_findings_omitted');
    if (current.context.scanStatus !== current.scan.scan_status) reasons.push('current_context_mismatch');
    if (hasDuplicateIds(current.scan.findings)) reasons.push('current_duplicate_finding_id');
    if (!hasConsistentCounts(current.scan)) reasons.push('current_count_inconsistent');
  }

  if (baseline && current) {
    if (baseline === current || baseline.context === current.context) reasons.push('same_scan_snapshot');
    if (baseline.context.targetId !== current.context.targetId) reasons.push('target_mismatch');
    if (baseline.context.ruleProfileId !== current.context.ruleProfileId
      || baseline.context.experimental !== current.context.experimental) reasons.push('rule_profile_mismatch');
    if (!baseline.scan.semgrep_version || !current.scan.semgrep_version) reasons.push('semgrep_version_unavailable');
    else if (baseline.scan.semgrep_version !== current.scan.semgrep_version) reasons.push('semgrep_version_mismatch');
  }

  if (reasons.length > 0 || !baseline || !current) return { comparable: false, reasons, groups: null };

  const baselineById = new Map(baseline.scan.findings.map((finding) => [finding.finding_id, finding]));
  const currentById = new Map(current.scan.findings.map((finding) => [finding.finding_id, finding]));
  const currentOnly = [...currentById].filter(([id]) => !baselineById.has(id)).map(([, finding]) => finding);
  const shared = [...currentById].filter(([id]) => baselineById.has(id)).map(([, finding]) => finding);
  const baselineOnly = [...baselineById].filter(([id]) => !currentById.has(id)).map(([, finding]) => finding);
  const byFindingId = (left: ApiFinding, right: ApiFinding) => left.finding_id.localeCompare(right.finding_id);

  return {
    comparable: true,
    reasons: [],
    groups: {
      currentOnly: currentOnly.sort(byFindingId),
      shared: shared.sort(byFindingId),
      baselineOnly: baselineOnly.sort(byFindingId),
    },
  };
}
