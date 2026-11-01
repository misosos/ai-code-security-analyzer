import { parseScan, type ApiFinding, type FindingKind, type ScanResponse, type ScanStatus, type Severity } from '../../api/types';
import { MAX_ANALYST_NOTE_BYTES, type AnalystReviewState, type AnalystReviewStatus } from './analystReview';
import type { ScanContext } from './markdownExport';

export const ANALYST_REVIEW_BACKUP_SCHEMA = 'analyst-review-backup/v1' as const;
export const ANALYST_REVIEW_BACKUP_FILENAME = 'ai-code-security-analyst-review-backup.json';
export const MAX_ANALYST_REVIEW_BACKUP_BYTES = 256 * 1024;
const MAX_BACKUP_FINDINGS = 50;
const statuses: readonly AnalystReviewStatus[] = ['pending', 'needs_followup', 'reviewed'];
const severities: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const kinds: readonly FindingKind[] = ['taint', 'pattern', 'unclassified'];
const scanStatuses: readonly ScanStatus[] = ['completed', 'partial', 'execution_failed', 'not_installed', 'invalid_json', 'timed_out', 'output_limit_exceeded'];

export interface BackupFinding {
  finding_id: string;
  rule_id: string;
  file_path: string | null;
  line_number: number | null;
  severity: Severity;
  finding_kind: FindingKind;
  review_status: AnalystReviewStatus;
  note?: string;
}

export interface AnalystReviewBackup {
  schema_version: typeof ANALYST_REVIEW_BACKUP_SCHEMA;
  scan_context: {
    target_id: string;
    rule_profile_id: string;
    experimental: boolean;
    semgrep_version: string | null;
    scan_status: ScanStatus;
    received_at: string;
    finding_count: number;
    displayed_finding_count: number;
    omitted_finding_count: number;
  };
  findings: BackupFinding[];
}

export type RestoreBlockReason = 'current_scan_not_completed' | 'current_findings_omitted' | 'backup_scan_not_completed'
  | 'backup_findings_omitted' | 'target_mismatch' | 'rule_profile_mismatch' | 'experimental_mismatch'
  | 'semgrep_version_unavailable' | 'semgrep_version_mismatch' | 'finding_set_mismatch' | 'finding_metadata_mismatch'
  | 'scan_count_inconsistent' | 'current_context_mismatch';

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, allowed: readonly string[]) => Object.keys(value).length === allowed.length && Object.keys(value).every((key) => allowed.includes(key));
const safeId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const safeFindingId = (value: unknown): value is string => typeof value === 'string' && /^semgrep:[a-f0-9]{24}$/.test(value);
const safeRuleId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,256}$/.test(value);
const safePath = (value: unknown): value is string | null => value === null || (typeof value === 'string' && value.length <= 1024
  && !value.startsWith('/') && !value.startsWith('\\') && !/^[A-Za-z]:/.test(value) && !value.includes('\\') && !/[\p{C}]/u.test(value)
  && value.split('/').every((part) => part.length > 0 && part !== '.' && part !== '..'));

function validateReviewState(state: AnalystReviewState, findings: readonly ApiFinding[]): Map<string, { status: AnalystReviewStatus; note: string }> {
  if (!(state instanceof Map)) throw new Error('backup_review_state_invalid');
  const ids = new Set(findings.map((finding) => finding.finding_id));
  const result = new Map<string, { status: AnalystReviewStatus; note: string }>();
  for (const [id, entry] of state) {
    if (!ids.has(id) || !entry || !statuses.includes(entry.status) || typeof entry.note !== 'string'
      || new TextEncoder().encode(entry.note).byteLength > MAX_ANALYST_NOTE_BYTES) throw new Error('backup_review_state_invalid');
    result.set(id, { status: entry.status, note: entry.note });
  }
  return result;
}

function validateContext(context: ScanContext, scan: ScanResponse): void {
  if (!context || !safeId(context.targetId) || !safeId(context.ruleProfileId) || typeof context.experimental !== 'boolean'
    || context.scanStatus !== scan.scan_status || typeof context.receivedAt !== 'string' || context.receivedAt.length > 64
    || !Number.isFinite(Date.parse(context.receivedAt))) throw new Error('backup_scan_context_invalid');
}

/** Builds an archival backup of exactly the current validated API response. */
export function createAnalystReviewBackup(
  context: ScanContext,
  input: ScanResponse,
  state: AnalystReviewState,
  includeNotes = false,
): string {
  let scan: ScanResponse;
  try { scan = parseScan(input); } catch { throw new Error('backup_scan_invalid'); }
  validateContext(context, scan);
  if (typeof includeNotes !== 'boolean') throw new Error('backup_option_invalid');
  if (scan.findings.length > MAX_BACKUP_FINDINGS) throw new Error('backup_finding_limit_exceeded');
  const reviews = validateReviewState(state, scan.findings);
  const findings: BackupFinding[] = [...scan.findings]
    .sort((a, b) => a.finding_id.localeCompare(b.finding_id))
    .map((finding) => {
      const review = reviews.get(finding.finding_id);
      return {
        finding_id: finding.finding_id, rule_id: finding.rule_id, file_path: finding.file_path,
        line_number: finding.line_number, severity: finding.severity, finding_kind: finding.finding_kind,
        review_status: review?.status ?? 'pending',
        ...(includeNotes && review?.note ? { note: review.note } : {}),
      };
    });
  const backup: AnalystReviewBackup = {
    schema_version: ANALYST_REVIEW_BACKUP_SCHEMA,
    scan_context: {
      target_id: context.targetId, rule_profile_id: context.ruleProfileId, experimental: context.experimental,
      semgrep_version: scan.semgrep_version, scan_status: scan.scan_status, received_at: context.receivedAt,
      finding_count: scan.finding_count, displayed_finding_count: scan.displayed_finding_count,
      omitted_finding_count: scan.omitted_finding_count,
    },
    findings,
  };
  const json = `${JSON.stringify(backup, null, 2)}\n`;
  if (new TextEncoder().encode(json).byteLength > MAX_ANALYST_REVIEW_BACKUP_BYTES) throw new Error('backup_size_limit_exceeded');
  return json;
}

function validateBackup(value: unknown): AnalystReviewBackup {
  if (!isRecord(value) || !exactKeys(value, ['schema_version', 'scan_context', 'findings']) || value.schema_version !== ANALYST_REVIEW_BACKUP_SCHEMA
    || !isRecord(value.scan_context) || !exactKeys(value.scan_context, ['target_id','rule_profile_id','experimental','semgrep_version','scan_status','received_at','finding_count','displayed_finding_count','omitted_finding_count'])
    || !Array.isArray(value.findings) || value.findings.length > MAX_BACKUP_FINDINGS) throw new Error('backup_schema_invalid');
  const context = value.scan_context;
  if (!safeId(context.target_id) || !safeId(context.rule_profile_id) || typeof context.experimental !== 'boolean'
    || (context.semgrep_version !== null && (typeof context.semgrep_version !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(context.semgrep_version)))
    || typeof context.scan_status !== 'string' || !scanStatuses.includes(context.scan_status as ScanStatus)
    || typeof context.received_at !== 'string' || context.received_at.length > 64 || !Number.isFinite(Date.parse(context.received_at))) throw new Error('backup_context_invalid');
  const counts = ['finding_count','displayed_finding_count','omitted_finding_count'] as const;
  if (counts.some((key) => !Number.isSafeInteger(context[key]) || Number(context[key]) < 0)
    || Number(context.finding_count) !== Number(context.displayed_finding_count) + Number(context.omitted_finding_count)
    || Number(context.displayed_finding_count) !== value.findings.length) throw new Error('backup_counts_invalid');
  const seen = new Set<string>();
  const findings = value.findings.map((item): BackupFinding => {
    if (!isRecord(item) || !(exactKeys(item, ['finding_id','rule_id','file_path','line_number','severity','finding_kind','review_status'])
      || exactKeys(item, ['finding_id','rule_id','file_path','line_number','severity','finding_kind','review_status','note']))
      || !safeFindingId(item.finding_id) || seen.has(item.finding_id) || !safeRuleId(item.rule_id) || !safePath(item.file_path)
      || (item.line_number !== null && (!Number.isSafeInteger(item.line_number) || Number(item.line_number) < 1))
      || typeof item.severity !== 'string' || !severities.includes(item.severity as Severity)
      || typeof item.finding_kind !== 'string' || !kinds.includes(item.finding_kind as FindingKind)
      || typeof item.review_status !== 'string' || !statuses.includes(item.review_status as AnalystReviewStatus)
      || ('note' in item && (typeof item.note !== 'string' || new TextEncoder().encode(item.note).byteLength > MAX_ANALYST_NOTE_BYTES))) throw new Error('backup_finding_invalid');
    seen.add(item.finding_id);
    return {
      finding_id: item.finding_id, rule_id: item.rule_id, file_path: item.file_path,
      line_number: item.line_number as number | null, severity: item.severity as Severity,
      finding_kind: item.finding_kind as FindingKind, review_status: item.review_status as AnalystReviewStatus,
      ...('note' in item ? { note: item.note as string } : {}),
    };
  });
  return {
    schema_version: ANALYST_REVIEW_BACKUP_SCHEMA,
    scan_context: {
      target_id: context.target_id, rule_profile_id: context.rule_profile_id, experimental: context.experimental,
      semgrep_version: context.semgrep_version as string | null, scan_status: context.scan_status as ScanStatus,
      received_at: context.received_at, finding_count: Number(context.finding_count),
      displayed_finding_count: Number(context.displayed_finding_count), omitted_finding_count: Number(context.omitted_finding_count),
    },
    findings,
  };
}

/** Decodes and validates untrusted file bytes. No parsed object is merged into application state. */
export function parseAnalystReviewBackup(bytes: Uint8Array): AnalystReviewBackup {
  if (!ArrayBuffer.isView(bytes) || bytes.BYTES_PER_ELEMENT !== 1 || bytes.byteLength > MAX_ANALYST_REVIEW_BACKUP_BYTES) throw new Error('backup_size_limit_exceeded');
  let decoded: string;
  try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new Error('backup_utf8_invalid'); }
  let parsed: unknown;
  try { rejectDuplicateJsonKeys(decoded); parsed = JSON.parse(decoded) as unknown; } catch (error) {
    if (error instanceof Error && ['backup_duplicate_key', 'backup_depth_limit_exceeded'].includes(error.message)) throw error;
    throw new Error('backup_json_invalid');
  }
  return validateBackup(parsed);
}

function rejectDuplicateJsonKeys(source: string): void {
  const stack: Array<{ kind: 'object' | 'array'; expectsKey: boolean; keys: Set<string> }> = [];
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === '"') {
      const start = index;
      index += 1;
      while (index < source.length) {
        if (source[index] === '\\') { index += 2; continue; }
        if (source[index] === '"') break;
        index += 1;
      }
      if (index >= source.length) return; // JSON.parse reports the malformed string.
      const container = stack[stack.length - 1];
      if (container?.kind === 'object' && container.expectsKey) {
        const key = JSON.parse(source.slice(start, index + 1)) as string;
        if (container.keys.has(key)) throw new Error('backup_duplicate_key');
        container.keys.add(key);
        container.expectsKey = false;
      }
    } else if (char === '{') {
      stack.push({ kind: 'object', expectsKey: true, keys: new Set() });
      if (stack.length > 8) throw new Error('backup_depth_limit_exceeded');
    } else if (char === '[') {
      stack.push({ kind: 'array', expectsKey: false, keys: new Set() });
      if (stack.length > 8) throw new Error('backup_depth_limit_exceeded');
    }
    else if (char === '}' || char === ']') stack.pop();
    else if (char === ',' && stack[stack.length - 1]?.kind === 'object') stack[stack.length - 1].expectsKey = true;
  }
}

export function validateBackupForRestore(backup: AnalystReviewBackup, context: ScanContext, input: ScanResponse): RestoreBlockReason[] {
  let scan: ScanResponse;
  try { scan = parseScan(input); } catch { return ['scan_count_inconsistent']; }
  const reasons: RestoreBlockReason[] = [];
  if (context.scanStatus !== scan.scan_status || !safeId(context.targetId) || !safeId(context.ruleProfileId)) reasons.push('current_context_mismatch');
  if (!scan.completed || scan.scan_status !== 'completed') reasons.push('current_scan_not_completed');
  if (scan.omitted_finding_count !== 0) reasons.push('current_findings_omitted');
  if (backup.scan_context.scan_status !== 'completed') reasons.push('backup_scan_not_completed');
  if (backup.scan_context.omitted_finding_count !== 0) reasons.push('backup_findings_omitted');
  if (context.targetId !== backup.scan_context.target_id) reasons.push('target_mismatch');
  if (context.ruleProfileId !== backup.scan_context.rule_profile_id) reasons.push('rule_profile_mismatch');
  if (context.experimental !== backup.scan_context.experimental) reasons.push('experimental_mismatch');
  if (!scan.semgrep_version || !backup.scan_context.semgrep_version) reasons.push('semgrep_version_unavailable');
  else if (scan.semgrep_version !== backup.scan_context.semgrep_version) reasons.push('semgrep_version_mismatch');
  if (scan.finding_count !== scan.displayed_finding_count + scan.omitted_finding_count || scan.displayed_finding_count !== scan.findings.length
    || backup.scan_context.finding_count !== backup.scan_context.displayed_finding_count + backup.scan_context.omitted_finding_count
    || backup.scan_context.displayed_finding_count !== backup.findings.length) reasons.push('scan_count_inconsistent');
  const currentById = new Map(scan.findings.map((finding) => [finding.finding_id, finding]));
  if (currentById.size !== backup.findings.length || backup.findings.some((finding) => !currentById.has(finding.finding_id))) reasons.push('finding_set_mismatch');
  else if (backup.findings.some((saved) => !sameFinding(saved, currentById.get(saved.finding_id)!))) reasons.push('finding_metadata_mismatch');
  return [...new Set(reasons)];
}

function sameFinding(saved: BackupFinding, current: ApiFinding): boolean {
  return saved.rule_id === current.rule_id && saved.file_path === current.file_path && saved.line_number === current.line_number
    && saved.severity === current.severity && saved.finding_kind === current.finding_kind;
}

export function downloadAnalystReviewBackup(json: string): void {
  if (new TextEncoder().encode(json).byteLength > MAX_ANALYST_REVIEW_BACKUP_BYTES) throw new Error('backup_size_limit_exceeded');
  const blob = new Blob([json], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = ANALYST_REVIEW_BACKUP_FILENAME; anchor.hidden = true;
  document.body.append(anchor);
  try { anchor.click(); } finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
