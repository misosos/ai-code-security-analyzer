import { describe, expect, it } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { emptyAnalystReviewState, setAnalystReviewNote, setAnalystReviewStatus } from '../src/features/scans/analystReview';
import {
  ANALYST_REVIEW_BACKUP_SCHEMA, createAnalystReviewBackup, MAX_ANALYST_REVIEW_BACKUP_BYTES,
  parseAnalystReviewBackup, validateBackupForRestore,
} from '../src/features/scans/analystReviewBackup';
import type { ScanContext } from '../src/features/scans/markdownExport';

const context: ScanContext = { targetId: 'project_a', targetLabel: 'Synthetic project', ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline', experimental: false, scanStatus: 'completed', receivedAt: '2026-10-01T12:00:00.000Z' };
const finding = (id: string, extra: Partial<ApiFinding> = {}): ApiFinding => ({ finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: 'baseline.rule-1', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/a.ts', line_number: 4, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null, ...extra });
const scan = (findings: ApiFinding[], extra: Partial<ScanResponse> = {}): ScanResponse => ({ scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'], ...extra });
const bytes = (value: string) => new TextEncoder().encode(value);
const createBackup = (findings = [finding('1')], includeNotes = false, state = emptyAnalystReviewState, response = scan(findings)) =>
  parseAnalystReviewBackup(bytes(createAnalystReviewBackup(context, response, state, includeNotes)));

describe('analyst review JSON backup and restore validation', () => {
  it('exports fixed schema, all visible findings deterministically, and excludes notes by default', () => {
    const findings = [finding('2'), finding('1')];
    let state = setAnalystReviewStatus(emptyAnalystReviewState, findings, findings[0].finding_id, 'reviewed')!;
    state = setAnalystReviewNote(state, findings, findings[0].finding_id, '내부 메모').state;
    const json = createAnalystReviewBackup(context, scan(findings), state);
    expect(JSON.parse(json).schema_version).toBe(ANALYST_REVIEW_BACKUP_SCHEMA);
    expect(json).not.toContain('내부 메모');
    expect(createAnalystReviewBackup(context, scan([...findings].reverse()), state)).toBe(json);
    expect(parseAnalystReviewBackup(bytes(json)).findings.map((item) => item.finding_id)).toEqual([...findings].map((item) => item.finding_id).sort());
  });

  it('includes a note only with explicit option and preserves manual status separately', () => {
    const item = finding('1');
    let state = setAnalystReviewStatus(emptyAnalystReviewState, [item], item.finding_id, 'needs_followup')!;
    state = setAnalystReviewNote(state, [item], item.finding_id, '검토 메모').state;
    const backup = createBackup([item], true, state);
    expect(backup.findings[0]).toMatchObject({ review_status: 'needs_followup', note: '검토 메모' });
    expect(item.verification_status).toBe('unverified');
    expect(item.evidence_validation_status).toBe('validated');
  });

  it('accepts current complete identical scan context and blocks any identity/context mismatch', () => {
    const items = [finding('1')];
    const backup = createBackup(items);
    expect(validateBackupForRestore(backup, context, scan(items))).toEqual([]);
    expect(validateBackupForRestore(backup, { ...context, targetId: 'other' }, scan(items))).toContain('target_mismatch');
    expect(validateBackupForRestore(backup, { ...context, ruleProfileId: 'other' }, scan(items))).toContain('rule_profile_mismatch');
    expect(validateBackupForRestore(backup, { ...context, experimental: true }, scan(items))).toContain('experimental_mismatch');
    expect(validateBackupForRestore(backup, context, scan(items, { semgrep_version: '1.182.2' }))).toContain('semgrep_version_mismatch');
    expect(validateBackupForRestore(backup, context, scan([finding('2')]))).toContain('finding_set_mismatch');
    expect(validateBackupForRestore(backup, context, scan([finding('1', { line_number: 5 })]))).toContain('finding_metadata_mismatch');
  });

  it('blocks partial, omitted, failed and malformed UTF-8 inputs', () => {
    const item = finding('1'); const backup = createBackup([item]);
    expect(validateBackupForRestore(backup, context, scan([item], { scan_status: 'partial', completed: false }))).toContain('current_scan_not_completed');
    expect(() => parseAnalystReviewBackup(new Uint8Array([0xc3, 0x28]))).toThrow('backup_utf8_invalid');
    expect(() => parseAnalystReviewBackup(bytes('{"schema_version":"analyst-review-backup/v1","schema_version":"analyst-review-backup/v1","scan_context":{},"findings":[]}'))).toThrow('backup_duplicate_key');
    expect(() => parseAnalystReviewBackup(bytes(`${'{'.repeat(10)}${'}'.repeat(10)}`))).toThrow('backup_depth_limit_exceeded');
    const omitted = createBackup([item], false, emptyAnalystReviewState, scan([item], { finding_count: 2, displayed_finding_count: 1, omitted_finding_count: 1, severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 } }));
    expect(validateBackupForRestore(omitted, context, scan([item]))).toContain('backup_findings_omitted');
    expect(validateBackupForRestore(backup, context, scan([item], { scan_status: 'execution_failed', completed: false }))).toContain('current_scan_not_completed');
  });

  it('rejects unknown keys, duplicate IDs, invalid status, unsafe paths, oversized notes and prototype keys', () => {
    const valid = JSON.parse(createAnalystReviewBackup(context, scan([finding('1')]), emptyAnalystReviewState));
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify({ ...valid, unexpected: true })))).toThrow('backup_schema_invalid');
    const dup = structuredClone(valid); dup.findings.push({ ...dup.findings[0] }); dup.scan_context.finding_count = 2; dup.scan_context.displayed_finding_count = 2;
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify(dup)))).toThrow('backup_finding_invalid');
    const invalidStatus = structuredClone(valid); invalidStatus.findings[0].review_status = 'confirmed';
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify(invalidStatus)))).toThrow('backup_finding_invalid');
    const unsafePath = structuredClone(valid); unsafePath.findings[0].file_path = '../secret';
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify(unsafePath)))).toThrow('backup_finding_invalid');
    const absolutePath = structuredClone(valid); absolutePath.findings[0].file_path = '/private/project/a.ts';
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify(absolutePath)))).toThrow('backup_finding_invalid');
    const tooLong = structuredClone(valid); tooLong.findings[0].note = '가'.repeat(683);
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify(tooLong)))).toThrow('backup_finding_invalid');
    expect(() => parseAnalystReviewBackup(bytes('{"schema_version":"analyst-review-backup/v1","__proto__":{},"scan_context":{},"findings":[]}'))).toThrow();
    const unknownSchema = structuredClone(valid); unknownSchema.schema_version = 'analyst-review-backup/v2';
    expect(() => parseAnalystReviewBackup(bytes(JSON.stringify(unknownSchema)))).toThrow('backup_schema_invalid');
  });

  it('enforces 256 KiB before parsing and creates no partial payload', () => {
    expect(() => parseAnalystReviewBackup(new Uint8Array(MAX_ANALYST_REVIEW_BACKUP_BYTES + 1))).toThrow('backup_size_limit_exceeded');
    const tooLarge = '가'.repeat(MAX_ANALYST_REVIEW_BACKUP_BYTES);
    expect(() => parseAnalystReviewBackup(bytes(tooLarge))).toThrow('backup_size_limit_exceeded');
    const findings = Array.from({ length: 50 }, (_, index) => finding(index.toString(16)));
    let state = emptyAnalystReviewState;
    for (const item of findings) state = setAnalystReviewNote(state, findings, item.finding_id, '\0'.repeat(2048)).state;
    const fullScan = scan(findings, { finding_count: 50, displayed_finding_count: 50, severity_counts: { critical: 0, high: 50, medium: 0, low: 0, info: 0 } });
    expect(() => createAnalystReviewBackup(context, fullScan, state, true)).toThrow('backup_size_limit_exceeded');
  });
});
