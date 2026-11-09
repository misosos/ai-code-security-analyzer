import type { ApiFinding, ScanResponse } from '../../api/types';

export type AnalystReviewStatus = 'pending' | 'needs_followup' | 'reviewed';

export interface AnalystReviewEntry {
  status: AnalystReviewStatus;
  note: string;
}

export type AnalystReviewState = ReadonlyMap<string, AnalystReviewEntry>;
export type AnalystReviewFilter = 'all' | AnalystReviewStatus;

export const MAX_ANALYST_NOTE_BYTES = 2 * 1024;
export const emptyAnalystReviewState: AnalystReviewState = new Map();
export const defaultAnalystReviewEntry: AnalystReviewEntry = Object.freeze({ status: 'pending', note: '' });

const validStatuses: readonly AnalystReviewStatus[] = ['pending', 'needs_followup', 'reviewed'];
const findingIdPattern = /^semgrep:[a-f0-9]{24}$/;

function includesFinding(findings: readonly ApiFinding[], findingId: string): boolean {
  return findingIdPattern.test(findingId) && findings.some((finding) => finding.finding_id === findingId);
}

export function getAnalystReviewEntry(
  state: AnalystReviewState,
  findings: readonly ApiFinding[],
  findingId: string,
): AnalystReviewEntry {
  if (!includesFinding(findings, findingId)) return defaultAnalystReviewEntry;
  return state.get(findingId) ?? defaultAnalystReviewEntry;
}

export function setAnalystReviewStatus(
  state: AnalystReviewState,
  findings: readonly ApiFinding[],
  findingId: string,
  status: unknown,
): AnalystReviewState | null {
  if (!includesFinding(findings, findingId) || typeof status !== 'string' || !validStatuses.includes(status as AnalystReviewStatus)) return null;
  const entry = getAnalystReviewEntry(state, findings, findingId);
  const next = new Map(state);
  next.set(findingId, { ...entry, status: status as AnalystReviewStatus });
  return next;
}

export type AnalystNoteUpdate =
  | { state: AnalystReviewState; accepted: true }
  | { state: AnalystReviewState; accepted: false; reason: 'finding_not_current' | 'note_too_large' };

export function setAnalystReviewNote(
  state: AnalystReviewState,
  findings: readonly ApiFinding[],
  findingId: string,
  note: string,
): AnalystNoteUpdate {
  if (!includesFinding(findings, findingId)) return { state, accepted: false, reason: 'finding_not_current' };
  if (new TextEncoder().encode(note).byteLength > MAX_ANALYST_NOTE_BYTES) return { state, accepted: false, reason: 'note_too_large' };
  const entry = getAnalystReviewEntry(state, findings, findingId);
  const next = new Map(state);
  next.set(findingId, { ...entry, note });
  return { state: next, accepted: true };
}

export function countAnalystReviewStatuses(
  findings: readonly ApiFinding[],
  state: AnalystReviewState,
): Record<AnalystReviewStatus, number> {
  const counts: Record<AnalystReviewStatus, number> = { pending: 0, needs_followup: 0, reviewed: 0 };
  for (const finding of findings) counts[getAnalystReviewEntry(state, findings, finding.finding_id).status] += 1;
  return counts;
}

export function filterFindingsByAnalystStatus(
  findings: readonly ApiFinding[],
  state: AnalystReviewState,
  filter: AnalystReviewFilter,
): ApiFinding[] {
  return filter === 'all'
    ? [...findings]
    : findings.filter((finding) => getAnalystReviewEntry(state, findings, finding.finding_id).status === filter);
}

export function hasAnalystReviewWork(findings: readonly ApiFinding[], state: AnalystReviewState): boolean {
  return findings.some((finding) => {
    const entry = getAnalystReviewEntry(state, findings, finding.finding_id);
    return entry.status !== 'pending' || entry.note.length > 0;
  });
}

/**
 * Review records belong to the findings of the scan they were written on. A rescan may replace them only
 * when it produced a normally completed response; partial or failed responses never replace prior records.
 */
export function rescanReplacesAnalystReview(result: Pick<ScanResponse, 'scan_status' | 'completed'>): boolean {
  return result.scan_status === 'completed' && result.completed;
}
