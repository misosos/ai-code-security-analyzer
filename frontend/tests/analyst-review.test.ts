import { describe, expect, it } from 'vitest';
import type { ApiFinding } from '../src/api/types';
import {
  countAnalystReviewStatuses, emptyAnalystReviewState, filterFindingsByAnalystStatus,
  getAnalystReviewEntry, hasAnalystReviewWork, MAX_ANALYST_NOTE_BYTES,
  setAnalystReviewNote, setAnalystReviewStatus,
} from '../src/features/scans/analystReview';

const finding = (id: string, verification_status: ApiFinding['verification_status'] = 'unverified'): ApiFinding => ({
  finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: 'baseline.sample', severity: 'high',
  verification_status, finding_kind: 'pattern', file_path: 'src/sample.ts', line_number: 4,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null,
});

describe('analyst review state', () => {
  it('starts pending and keeps status changes independent per current Finding', () => {
    const findings = [finding('1'), finding('2')];
    expect(getAnalystReviewEntry(emptyAnalystReviewState, findings, findings[0].finding_id)).toEqual({ status: 'pending', note: '' });
    const followup = setAnalystReviewStatus(emptyAnalystReviewState, findings, findings[0].finding_id, 'needs_followup')!;
    const reviewed = setAnalystReviewStatus(followup, findings, findings[1].finding_id, 'reviewed')!;
    expect(getAnalystReviewEntry(reviewed, findings, findings[0].finding_id).status).toBe('needs_followup');
    expect(getAnalystReviewEntry(reviewed, findings, findings[1].finding_id).status).toBe('reviewed');
    expect(setAnalystReviewStatus(reviewed, findings, findings[0].finding_id, 'pending')?.get(findings[0].finding_id)?.status).toBe('pending');
  });

  it('keeps notes independent and enforces a UTF-8 2 KiB limit without replacing valid text', () => {
    const findings = [finding('1'), finding('2')];
    const saved = setAnalystReviewNote(emptyAnalystReviewState, findings, findings[0].finding_id, '확인 메모');
    expect(saved.accepted).toBe(true);
    if (!saved.accepted) return;
    const boundary = setAnalystReviewNote(saved.state, findings, findings[0].finding_id, '가'.repeat(682));
    expect(boundary.accepted).toBe(true);
    if (!boundary.accepted) return;
    expect(new TextEncoder().encode(boundary.state.get(findings[0].finding_id)?.note).byteLength).toBeLessThanOrEqual(MAX_ANALYST_NOTE_BYTES);
    const tooLong = setAnalystReviewNote(boundary.state, findings, findings[0].finding_id, `${'가'.repeat(682)}가`);
    expect(tooLong).toEqual({ state: boundary.state, accepted: false, reason: 'note_too_large' });
    const second = setAnalystReviewNote(boundary.state, findings, findings[1].finding_id, '다른 메모');
    expect(second.accepted && second.state.get(findings[1].finding_id)?.note).toBe('다른 메모');
    expect(boundary.state.get(findings[1].finding_id)).toBeUndefined();
  });

  it('rejects unknown Finding IDs and invalid status values', () => {
    const findings = [finding('1')];
    expect(setAnalystReviewStatus(emptyAnalystReviewState, findings, 'semgrep:bad', 'reviewed')).toBeNull();
    expect(setAnalystReviewStatus(emptyAnalystReviewState, findings, findings[0].finding_id, 'confirmed_vulnerable')).toBeNull();
    expect(setAnalystReviewNote(emptyAnalystReviewState, findings, 'semgrep:bad', 'x')).toMatchObject({ accepted: false, reason: 'finding_not_current' });
  });

  it('derives counts and status filters from current findings only', () => {
    const findings = [finding('1'), finding('2'), finding('3')];
    let state = setAnalystReviewStatus(emptyAnalystReviewState, findings, findings[1].finding_id, 'needs_followup')!;
    state = setAnalystReviewStatus(state, findings, findings[2].finding_id, 'reviewed')!;
    expect(countAnalystReviewStatuses(findings, state)).toEqual({ pending: 1, needs_followup: 1, reviewed: 1 });
    expect(filterFindingsByAnalystStatus(findings, state, 'pending').map((item) => item.finding_id)).toEqual([findings[0].finding_id]);
    expect(filterFindingsByAnalystStatus(findings, state, 'all')).toHaveLength(3);
    expect(filterFindingsByAnalystStatus([findings[0]], state, 'reviewed')).toEqual([]);
  });

  it('does not alter API security classification or original response objects', () => {
    const original = finding('1');
    const snapshot = structuredClone(original);
    const findings = [original];
    const state = setAnalystReviewStatus(emptyAnalystReviewState, findings, original.finding_id, 'reviewed')!;
    const withNote = setAnalystReviewNote(state, findings, original.finding_id, '<script>alert(1)</script>');
    expect(withNote.accepted).toBe(true);
    expect(original).toEqual(snapshot);
    expect(original.verification_status).toBe('unverified');
    expect(original.evidence_validation_status).toBe('validated');
  });

  it('detects only analyst-authored changes for confirmation before discarding', () => {
    const findings = [finding('1')];
    expect(hasAnalystReviewWork(findings, emptyAnalystReviewState)).toBe(false);
    const withNote = setAnalystReviewNote(emptyAnalystReviewState, findings, findings[0].finding_id, '메모');
    expect(withNote.accepted && hasAnalystReviewWork(findings, withNote.state)).toBe(true);
    const reviewed = setAnalystReviewStatus(emptyAnalystReviewState, findings, findings[0].finding_id, 'reviewed')!;
    expect(hasAnalystReviewWork(findings, reviewed)).toBe(true);
    expect(hasAnalystReviewWork([], reviewed)).toBe(false);
  });
});
