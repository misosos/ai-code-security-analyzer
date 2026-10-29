export type ScanStatus = 'completed' | 'partial' | 'execution_failed' | 'not_installed' | 'invalid_json' | 'timed_out' | 'output_limit_exceeded';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingKind = 'pattern' | 'taint' | 'unclassified';
export type ClaimType = 'match_reported' | 'taint_rule_match_reported' | 'source_pattern_declared' | 'sink_pattern_declared' | 'match_location_observed' | 'source_location_identified' | 'sink_argument_location_identified' | 'flow_trace_available' | 'sanitizer_match_observed' | 'sanitizer_effectiveness_verified' | 'vulnerability_confirmed';
export type ClaimDecision = 'insufficient_evidence' | 'unavailable' | 'ambiguous' | 'unsupported_claim';
export type EvidenceReason = string;

export interface Health { status: 'ok'; service: 'ai-code-security-analyzer' }
export interface TargetOption { id: string; label: string }
export interface RuleProfileOption { id: string; label: string; experimental: boolean }
export interface Options { targets: TargetOption[]; rule_profiles: RuleProfileOption[] }
export interface RestrictedClaim { claim_type: ClaimType; decision: ClaimDecision; reason_codes: EvidenceReason[] }
export interface ApiFinding {
  finding_id: string; rule_id: string; severity: Severity; verification_status: 'unverified';
  finding_kind: FindingKind; file_path: string | null; line_number: number | null;
  evidence_validation_status: 'validated' | 'rejected' | 'unavailable';
  supported_claims: ClaimType[]; restricted_claims: RestrictedClaim[]; validation_error_code: string | null;
}
export interface ScanResponse {
  scan_status: ScanStatus; completed: boolean; semgrep_version: string | null;
  finding_count: number; displayed_finding_count: number; omitted_finding_count: number;
  severity_counts: Record<Severity, number>; issues: string[]; findings: ApiFinding[]; limitations: string[];
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const statuses: ScanStatus[] = ['completed', 'partial', 'execution_failed', 'not_installed', 'invalid_json', 'timed_out', 'output_limit_exceeded'];
const kinds: FindingKind[] = ['pattern', 'taint', 'unclassified'];
const claims: ClaimType[] = ['match_reported', 'taint_rule_match_reported', 'source_pattern_declared', 'sink_pattern_declared', 'match_location_observed', 'source_location_identified', 'sink_argument_location_identified', 'flow_trace_available', 'sanitizer_match_observed', 'sanitizer_effectiveness_verified', 'vulnerability_confirmed'];
const reasons = ['scan_state_unavailable','scan_partial','scan_not_complete','scan_failed','scan_result_inconsistent','taint_evidence_malformed','finding_not_in_scan','finding_association_ambiguous','finding_id_mismatch','rule_id_mismatch','file_path_mismatch','match_location_unavailable','match_location_malformed','match_location_not_sink_argument','taint_evidence_unavailable','engine_unverified','rule_declaration_unverified','rule_hash_mismatch','rule_declaration_mismatch','source_pattern_not_declared','sink_pattern_not_declared','source_location_unknown','source_location_unavailable','source_location_malformed','source_location_evidence_unavailable','sink_argument_location_unknown','sink_argument_location_unavailable','sink_argument_location_malformed','sink_argument_location_evidence_unavailable','flow_trace_absent','flow_trace_empty','flow_trace_unsupported','flow_trace_malformed','flow_trace_details_unavailable','sanitizer_pattern_not_declared','sanitizer_match_unknown','sanitizer_match_unavailable','sanitizer_match_malformed','sanitizer_match_details_unavailable','sanitizer_effectiveness_not_verified','independent_confirmation_required','rule_file_at_scan_time_unproven','analysis_scope_derived_from_engine_metadata','taint_match_not_vulnerability_confirmation','source_sink_path_unproven','sanitizer_match_not_effectiveness_proof','rule_declaration_not_observed_code','static_evidence_cannot_support_claim'] as const;
const issueCodes = ['semgrep_not_installed','semgrep_timeout','semgrep_output_limit','invalid_json','semgrep_failed','findings_omitted','evidence_unavailable'] as const;
const limitationCodes = ['finding_count_not_confirmed_vulnerability_count','scan_result_is_not_safety_proof','scan_partial','scan_failed','omitted_findings_not_individually_validated'] as const;
const decisions: ClaimDecision[] = ['insufficient_evidence', 'unavailable', 'ambiguous', 'unsupported_claim'];
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isString = (value: unknown): value is string => typeof value === 'string';
const isOneOf = <T extends string>(value: unknown, options: readonly T[]): value is T => typeof value === 'string' && options.includes(value as T);
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean { return Object.keys(value).every((key) => keys.includes(key)) && keys.every((key) => key in value); }

export function parseHealth(value: unknown): Health {
  if (!isRecord(value) || !exactKeys(value, ['status', 'service']) || value.status !== 'ok' || value.service !== 'ai-code-security-analyzer') throw new Error('invalid_api_response');
  return value as unknown as Health;
}
export function parseOptions(value: unknown): Options {
  if (!isRecord(value) || !exactKeys(value, ['targets', 'rule_profiles']) || !Array.isArray(value.targets) || !Array.isArray(value.rule_profiles)) throw new Error('invalid_api_response');
  const targets = value.targets.map((item) => {
    if (!isRecord(item) || !exactKeys(item, ['id', 'label']) || !isString(item.id) || !/^[A-Za-z0-9_-]{1,64}$/.test(item.id) || !isString(item.label) || item.label.length > 128 || /[\p{C}]/u.test(item.label)) throw new Error('invalid_api_response');
    return { id: item.id, label: item.label };
  });
  const rule_profiles = value.rule_profiles.map((item) => {
    if (!isRecord(item) || !exactKeys(item, ['id', 'label', 'experimental']) || !isString(item.id) || !/^[A-Za-z0-9_-]{1,64}$/.test(item.id) || !isString(item.label) || item.label.length > 128 || /[\p{C}]/u.test(item.label) || typeof item.experimental !== 'boolean') throw new Error('invalid_api_response');
    return { id: item.id, label: item.label, experimental: item.experimental };
  });
  return { targets, rule_profiles };
}
function parseFinding(value: unknown): ApiFinding {
  if (!isRecord(value) || !exactKeys(value, ['finding_id','rule_id','severity','verification_status','finding_kind','file_path','line_number','evidence_validation_status','supported_claims','restricted_claims','validation_error_code'])) throw new Error('invalid_api_response');
  if (!isString(value.finding_id) || !/^semgrep:[a-f0-9]{24}$/.test(value.finding_id) || !isString(value.rule_id) || !/^[A-Za-z0-9_.:-]{1,256}$/.test(value.rule_id)) throw new Error('invalid_api_response');
  if (!isOneOf(value.severity, severities) || value.verification_status !== 'unverified' || !isOneOf(value.finding_kind, kinds)) throw new Error('invalid_api_response');
  if (value.file_path !== null && (!isString(value.file_path) || value.file_path.startsWith('/') || value.file_path.includes('\\') || value.file_path.includes(':') || value.file_path.split('/').some((part) => !part || part === '.' || part === '..') || /[\p{C}]/u.test(value.file_path))) throw new Error('invalid_api_response');
  if (value.line_number !== null && (!Number.isSafeInteger(value.line_number) || Number(value.line_number) < 1)) throw new Error('invalid_api_response');
  if (!isOneOf(value.evidence_validation_status, ['validated','rejected','unavailable'] as const) || !Array.isArray(value.supported_claims) || !Array.isArray(value.restricted_claims)) throw new Error('invalid_api_response');
  if (value.supported_claims.some((claim) => !isOneOf(claim, claims))) throw new Error('invalid_api_response');
  const restricted = value.restricted_claims.map((claim) => {
    if (!isRecord(claim) || !exactKeys(claim, ['claim_type','decision','reason_codes']) || !isOneOf(claim.claim_type, claims) || !isOneOf(claim.decision, decisions) || !Array.isArray(claim.reason_codes) || claim.reason_codes.length > 8 || claim.reason_codes.some((reason) => !isOneOf(reason, reasons))) throw new Error('invalid_api_response');
    return { claim_type: claim.claim_type, decision: claim.decision, reason_codes: claim.reason_codes as string[] };
  });
  const supportedSet = new Set(value.supported_claims as string[]);
  if (supportedSet.size !== value.supported_claims.length || new Set(restricted.map((claim) => claim.claim_type)).size !== restricted.length || restricted.some((claim) => supportedSet.has(claim.claim_type))) throw new Error('invalid_api_response');
  if (value.validation_error_code !== null && (!isString(value.validation_error_code) || !/^[a-z_]{1,64}$/.test(value.validation_error_code))) throw new Error('invalid_api_response');
  return { ...value, supported_claims: [...value.supported_claims] as ClaimType[], restricted_claims: restricted } as unknown as ApiFinding;
}
export function parseScan(value: unknown): ScanResponse {
  if (!isRecord(value) || !exactKeys(value, ['scan_status','completed','semgrep_version','finding_count','displayed_finding_count','omitted_finding_count','severity_counts','issues','findings','limitations'])) throw new Error('invalid_api_response');
  if (!isOneOf(value.scan_status, statuses) || typeof value.completed !== 'boolean' || value.completed !== (value.scan_status === 'completed')) throw new Error('invalid_api_response');
  if (value.semgrep_version !== null && (!isString(value.semgrep_version) || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(value.semgrep_version))) throw new Error('invalid_api_response');
  for (const key of ['finding_count','displayed_finding_count','omitted_finding_count']) if (!Number.isSafeInteger(value[key]) || Number(value[key]) < 0) throw new Error('invalid_api_response');
  if (!isRecord(value.severity_counts) || !exactKeys(value.severity_counts, severities)) throw new Error('invalid_api_response');
  const severityCounts = value.severity_counts;
  if (severities.some((s) => typeof severityCounts[s] !== 'number' || !Number.isSafeInteger(severityCounts[s]) || Number(severityCounts[s]) < 0)) throw new Error('invalid_api_response');
  if (!Array.isArray(value.issues) || value.issues.some((x) => !isOneOf(x, issueCodes)) || !Array.isArray(value.limitations) || value.limitations.some((x) => !isOneOf(x, limitationCodes)) || !Array.isArray(value.findings) || value.findings.length > 50) throw new Error('invalid_api_response');
  const findings = value.findings.map(parseFinding);
  const findingCount = value.finding_count as number;
  const displayedCount = value.displayed_finding_count as number;
  const omittedCount = value.omitted_finding_count as number;
  if (findings.length !== displayedCount || findingCount !== displayedCount + omittedCount) throw new Error('invalid_api_response');
  if (new Set(findings.map((finding) => finding.finding_id)).size !== findings.length || severities.reduce((total, severity) => total + Number(severityCounts[severity]), 0) !== findingCount) throw new Error('invalid_api_response');
  return { ...value, findings, issues: [...value.issues] as string[], limitations: [...value.limitations] as string[], severity_counts: { ...value.severity_counts } as Record<Severity, number> } as ScanResponse;
}
