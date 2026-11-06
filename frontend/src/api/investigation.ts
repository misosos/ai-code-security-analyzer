import { ApiError } from './client';
import { parseScan, type ScanResponse } from './types';

export type InvestigationCategory = 'currentOnly' | 'shared' | 'baselineOnly';
export type InvestigationAssessment =
  | 'COMPARABLE' | 'SUPPORTED' | 'CONTRADICTED' | 'UNDETERMINED' | 'INCOMPARABLE'
  | 'EXPLANATION_SUPPORTED' | 'MULTIPLE_EXPLANATIONS_POSSIBLE';
export type InvestigationPathObservation =
  | 'PATH_REPORTED_SCANNED' | 'PATH_EXPLICITLY_SKIPPED' | 'PATH_NOT_REPORTED'
  | 'SKIP_EVIDENCE_NOT_COLLECTED' | 'SCOPE_EVIDENCE_UNAVAILABLE'
  | 'FINDING_PATH_UNAVAILABLE' | 'CONFLICTING';
export type InvestigationLimitationCode =
  | 'scan_context_mismatch' | 'scan_reference_collision' | 'manifest_binding_invalid'
  | 'response_manifest_binding_invalid' | 'duplicate_finding_id' | 'finding_id_not_observed'
  | 'scan_incomplete' | 'finding_omitted' | 'rule_bytes_unverified'
  | 'loaded_rule_identity_unverified' | 'source_snapshot_not_collected'
  | 'scope_completeness_unverified' | 'path_reported_scanned' | 'path_explicitly_skipped'
  | 'path_not_reported' | 'skip_details_not_collected' | 'scope_evidence_unavailable'
  | 'finding_path_unavailable' | 'scanned_skipped_path_conflict'
  | 'evaluation_output_limit_exceeded' | 'scan_result_is_not_safety_proof';

export interface InvestigationScan { contract_version: 'investigation-scan/v1'; run_handle: string; scan: ScanResponse }
export interface InvestigationSession { contract_version: 'investigation-session/v1'; investigation_handle: string }
export interface InvestigationFinding {
  finding_id: string;
  category: InvestigationCategory;
  path_observation: InvestigationPathObservation | null;
  skip_hypothesis: InvestigationAssessment | null;
  source_snapshot_hypothesis: InvestigationAssessment | null;
  rule_identity_hypothesis: InvestigationAssessment | null;
}
export interface InvestigationEvaluation {
  contract_version: 'finding-disappearance-evaluation/v1';
  comparability: InvestigationAssessment;
  overall_assessment: InvestigationAssessment;
  findings: InvestigationFinding[];
  limitation_codes: InvestigationLimitationCode[];
}
export type RuleBytesComparisonStatus = 'SAME_SELECTED_BYTES' | 'DIFFERENT_SELECTED_BYTES' | 'UNVERIFIED' | 'INCOMPARABLE';
export interface RuleBytesComparison {
  contract_version: 'rule-bytes-comparison/v1';
  status: RuleBytesComparisonStatus;
  limitation_codes: ['selected_rule_bytes_only', 'loaded_rule_identity_unverified'];
}

const handlePattern = /^[A-Za-z0-9_-]{43}$/;
const categories: readonly InvestigationCategory[] = ['currentOnly', 'shared', 'baselineOnly'];
const assessments: readonly InvestigationAssessment[] = [
  'COMPARABLE', 'SUPPORTED', 'CONTRADICTED', 'UNDETERMINED', 'INCOMPARABLE',
  'EXPLANATION_SUPPORTED', 'MULTIPLE_EXPLANATIONS_POSSIBLE',
];
const pathObservations: readonly InvestigationPathObservation[] = [
  'PATH_REPORTED_SCANNED', 'PATH_EXPLICITLY_SKIPPED', 'PATH_NOT_REPORTED',
  'SKIP_EVIDENCE_NOT_COLLECTED', 'SCOPE_EVIDENCE_UNAVAILABLE', 'FINDING_PATH_UNAVAILABLE', 'CONFLICTING',
];
const limitations: readonly InvestigationLimitationCode[] = [
  'scan_context_mismatch', 'scan_reference_collision', 'manifest_binding_invalid',
  'response_manifest_binding_invalid', 'duplicate_finding_id', 'finding_id_not_observed',
  'scan_incomplete', 'finding_omitted', 'rule_bytes_unverified', 'loaded_rule_identity_unverified',
  'source_snapshot_not_collected', 'scope_completeness_unverified', 'path_reported_scanned',
  'path_explicitly_skipped', 'path_not_reported', 'skip_details_not_collected',
  'scope_evidence_unavailable', 'finding_path_unavailable', 'scanned_skipped_path_conflict',
  'evaluation_output_limit_exceeded', 'scan_result_is_not_safety_proof',
];
const errorCodes = new Set([
  'unauthorized', 'host_not_allowed', 'origin_not_allowed', 'invalid_content_type', 'invalid_request',
  'response_limit_exceeded', 'evidence_unavailable', 'binding_rejected', 'resource_limit',
  'internal_unavailable', 'evaluation_busy', 'unsupported_deployment', 'request_cancelled',
]);
type RecordValue = Record<string, unknown>;
const isRecord = (value: unknown): value is RecordValue => typeof value === 'object' && value !== null && !Array.isArray(value);
function exactKeys(value: RecordValue, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function requireRecord(value: unknown, keys: readonly string[]): RecordValue {
  if (!isRecord(value) || !exactKeys(value, keys)) throw new Error('invalid_api_response');
  return value;
}
function parseHandle(value: unknown): string {
  if (typeof value !== 'string' || !handlePattern.test(value)) throw new Error('invalid_api_response');
  return value;
}

export function parseInvestigationScan(value: unknown): InvestigationScan {
  const envelope = requireRecord(value, ['contract_version', 'run_handle', 'scan']);
  if (envelope.contract_version !== 'investigation-scan/v1') throw new Error('invalid_api_response');
  return { contract_version: 'investigation-scan/v1', run_handle: parseHandle(envelope.run_handle), scan: parseScan(envelope.scan) };
}

export function parseInvestigationSession(value: unknown): InvestigationSession {
  const envelope = requireRecord(value, ['contract_version', 'investigation_handle']);
  if (envelope.contract_version !== 'investigation-session/v1') throw new Error('invalid_api_response');
  return { contract_version: 'investigation-session/v1', investigation_handle: parseHandle(envelope.investigation_handle) };
}

export function parseInvestigationEvaluation(value: unknown): InvestigationEvaluation {
  const envelope = requireRecord(value, ['contract_version', 'comparability', 'overall_assessment', 'findings', 'limitation_codes']);
  if (envelope.contract_version !== 'finding-disappearance-evaluation/v1'
    || !assessments.includes(envelope.comparability as InvestigationAssessment)
    || !assessments.includes(envelope.overall_assessment as InvestigationAssessment)
    || !Array.isArray(envelope.findings) || envelope.findings.length > 100
    || !Array.isArray(envelope.limitation_codes) || envelope.limitation_codes.length > 64
    || envelope.limitation_codes.some((code) => !limitations.includes(code as InvestigationLimitationCode))
    || new Set(envelope.limitation_codes).size !== envelope.limitation_codes.length) throw new Error('invalid_api_response');

  const findings = envelope.findings.map((raw): InvestigationFinding => {
    const item = requireRecord(raw, ['finding_id', 'category', 'path_observation', 'skip_hypothesis', 'source_snapshot_hypothesis', 'rule_identity_hypothesis']);
    if (typeof item.finding_id !== 'string' || !/^semgrep:[a-f0-9]{24}$/.test(item.finding_id)
      || !categories.includes(item.category as InvestigationCategory)
      || (item.path_observation !== null && !pathObservations.includes(item.path_observation as InvestigationPathObservation))) throw new Error('invalid_api_response');
    for (const field of ['skip_hypothesis', 'source_snapshot_hypothesis', 'rule_identity_hypothesis'] as const) {
      if (item[field] !== null && !assessments.includes(item[field] as InvestigationAssessment)) throw new Error('invalid_api_response');
    }
    return {
      finding_id: item.finding_id,
      category: item.category as InvestigationCategory,
      path_observation: item.path_observation as InvestigationPathObservation | null,
      skip_hypothesis: item.skip_hypothesis as InvestigationAssessment | null,
      source_snapshot_hypothesis: item.source_snapshot_hypothesis as InvestigationAssessment | null,
      rule_identity_hypothesis: item.rule_identity_hypothesis as InvestigationAssessment | null,
    };
  });
  if (new Set(findings.map((item) => item.finding_id)).size !== findings.length) throw new Error('invalid_api_response');
  return {
    contract_version: 'finding-disappearance-evaluation/v1',
    comparability: envelope.comparability as InvestigationAssessment,
    overall_assessment: envelope.overall_assessment as InvestigationAssessment,
    findings,
    limitation_codes: envelope.limitation_codes as InvestigationLimitationCode[],
  };
}

export function parseRuleBytesComparison(value: unknown): RuleBytesComparison {
  const envelope = requireRecord(value, ['contract_version', 'status', 'limitation_codes']);
  const statuses: readonly RuleBytesComparisonStatus[] = ['SAME_SELECTED_BYTES', 'DIFFERENT_SELECTED_BYTES', 'UNVERIFIED', 'INCOMPARABLE'];
  if (envelope.contract_version !== 'rule-bytes-comparison/v1'
    || !statuses.includes(envelope.status as RuleBytesComparisonStatus)
    || !Array.isArray(envelope.limitation_codes)
    || envelope.limitation_codes.length !== 2
    || envelope.limitation_codes[0] !== 'selected_rule_bytes_only'
    || envelope.limitation_codes[1] !== 'loaded_rule_identity_unverified') throw new Error('invalid_api_response');
  return {
    contract_version: 'rule-bytes-comparison/v1',
    status: envelope.status as RuleBytesComparisonStatus,
    limitation_codes: ['selected_rule_bytes_only', 'loaded_rule_identity_unverified'],
  };
}

async function post(path: string, token: string, body: object, signal?: AbortSignal): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Local-API-Token': token },
      body: JSON.stringify(body),
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal,
    });
  } catch {
    throw new ApiError(0, 'connection_error');
  }
  if (!response.ok) {
    let code = 'request_failed';
    try {
      const value: unknown = await response.json();
      if (isRecord(value) && exactKeys(value, ['error']) && typeof value.error === 'string' && errorCodes.has(value.error)) code = value.error;
    } catch { /* Keep the closed generic code. */ }
    throw new ApiError(response.status, code);
  }
  return response;
}

async function jsonResponse(response: Response): Promise<unknown> {
  try { return await response.json(); }
  catch { throw new ApiError(response.status, 'invalid_api_response'); }
}

export const investigationApi = {
  async scan(token: string, targetId: string, ruleProfileId: string, signal?: AbortSignal): Promise<InvestigationScan> {
    const response = await post('/api/v2/investigation-scans', token, { target_id: targetId, rule_profile_id: ruleProfileId }, signal);
    return parseInvestigationScan(await jsonResponse(response));
  },
  async scanWithRuleBytes(token: string, targetId: string, ruleProfileId: string, signal?: AbortSignal): Promise<InvestigationScan> {
    const response = await post('/api/v2/investigation-scans/rule-bytes', token, { target_id: targetId, rule_profile_id: ruleProfileId }, signal);
    return parseInvestigationScan(await jsonResponse(response));
  },
  async createSession(token: string, baselineHandle: string, currentHandle: string, signal?: AbortSignal): Promise<InvestigationSession> {
    parseHandle(baselineHandle); parseHandle(currentHandle);
    const response = await post('/api/v2/investigations', token, { baseline_handle: baselineHandle, current_handle: currentHandle }, signal);
    return parseInvestigationSession(await jsonResponse(response));
  },
  async evaluate(token: string, investigationHandle: string, signal?: AbortSignal): Promise<InvestigationEvaluation> {
    parseHandle(investigationHandle);
    const response = await post('/api/v2/investigations/evaluate', token, { investigation_handle: investigationHandle }, signal);
    return parseInvestigationEvaluation(await jsonResponse(response));
  },
  async evaluateRuleBytes(token: string, investigationHandle: string, signal?: AbortSignal): Promise<RuleBytesComparison> {
    parseHandle(investigationHandle);
    const response = await post('/api/v2/investigations/rule-bytes/evaluate', token, { investigation_handle: investigationHandle }, signal);
    return parseRuleBytesComparison(await jsonResponse(response));
  },
  async release(token: string, kind: 'run' | 'investigation', handle: string, signal?: AbortSignal): Promise<void> {
    parseHandle(handle);
    const response = await post('/api/v2/investigation-release', token, { kind, handle }, signal);
    if (response.status !== 204) throw new ApiError(response.status, 'invalid_api_response');
    // A 204 has no representation; deliberately do not invoke JSON parsing.
  },
};
