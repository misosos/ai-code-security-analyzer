import { parseScan, type ApiFinding, type ScanResponse, type Severity } from '../../api/types';
import type { ScanContext } from './markdownExport';
import { getFindingReviewGuidance, hasKnownRuleGuidance } from './reviewGuidance';

export const SARIF_SCHEMA_URI = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';
export const SARIF_FILENAME = 'ai-code-security-results.sarif';
export const SARIF_MIME_TYPE = 'application/sarif+json;charset=utf-8';
export const MAX_SARIF_BYTES = 512 * 1024;

type SarifLevel = 'error' | 'warning' | 'note';
type JsonProperty = string | number | boolean | null | readonly JsonProperty[] | { readonly [key: string]: JsonProperty };

export interface SarifPropertyBag { [key: string]: JsonProperty }
export interface SarifRule {
  id: string;
  name?: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: SarifPropertyBag;
}
export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine: number };
  };
}
export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  properties: SarifPropertyBag;
}
export interface SarifReport {
  $schema: string;
  version: '2.1.0';
  runs: [{
    tool: { driver: {
      name: 'SAST Review Workspace';
      informationUri: string;
      rules: SarifRule[];
      properties: SarifPropertyBag;
    } };
    invocations: [{ executionSuccessful: boolean }];
    results: SarifResult[];
    properties: SarifPropertyBag;
  }];
}

const levelBySeverity: Record<Severity, SarifLevel> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note',
};

function validateContext(context: ScanContext, scan: ScanResponse): void {
  const absoluteLabel = (value: string) => value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value)
    || value.startsWith('\\\\') || value.startsWith('~/');
  if (!context || typeof context !== 'object'
    || typeof context.targetId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(context.targetId)
    || typeof context.ruleProfileId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(context.ruleProfileId)
    || typeof context.targetLabel !== 'string' || context.targetLabel.length > 128 || /[\p{C}]/u.test(context.targetLabel) || absoluteLabel(context.targetLabel)
    || typeof context.ruleProfileLabel !== 'string' || context.ruleProfileLabel.length > 128 || /[\p{C}]/u.test(context.ruleProfileLabel) || absoluteLabel(context.ruleProfileLabel)
    || typeof context.experimental !== 'boolean'
    || typeof context.receivedAt !== 'string' || context.receivedAt.length > 64 || !Number.isFinite(Date.parse(context.receivedAt))) {
    throw new Error('sarif_context_invalid');
  }
  if (context.scanStatus !== scan.scan_status) throw new Error('sarif_context_mismatch');
}

function relativeArtifactUri(path: string): string {
  // parseScan already enforces relative slash-delimited paths without traversal or controls.
  // Encode each component once so URI delimiters in a real filename cannot change the location.
  return path.split('/').map((segment) => encodeURIComponent(segment)).join('/');
}

function locationFor(finding: ApiFinding): SarifLocation[] | undefined {
  if (finding.file_path === null) return undefined;
  const physicalLocation: SarifLocation['physicalLocation'] = {
    artifactLocation: { uri: relativeArtifactUri(finding.file_path) },
  };
  if (finding.line_number !== null) physicalLocation.region = { startLine: finding.line_number };
  return [{ physicalLocation }];
}

function resultMessage(finding: ApiFinding): string {
  const guidance = getFindingReviewGuidance(finding.rule_id, finding.finding_kind);
  if (finding.evidence_validation_status === 'validated') {
    return `${guidance.finding} 보고된 근거 연결은 구조적으로 검증됐지만 실제 취약점 여부는 별도 확인이 필요합니다.`;
  }
  if (finding.evidence_validation_status === 'rejected') {
    return `${guidance.finding} 근거 연결 검증이 거부되어 확인된 구조적 근거로 취급할 수 없습니다.`;
  }
  return `${guidance.finding} 현재 응답에서는 근거 연결 상태를 확인할 수 없습니다.`;
}

function ruleFor(ruleId: string, representative: ApiFinding): SarifRule {
  const guidance = getFindingReviewGuidance(ruleId, representative.finding_kind);
  return {
    id: ruleId,
    shortDescription: { text: guidance.title },
    fullDescription: { text: guidance.finding },
    defaultConfiguration: { level: levelBySeverity[representative.severity] },
    properties: {
      detectionEngine: 'Semgrep',
      knownRuleGuidance: hasKnownRuleGuidance(ruleId),
    },
  };
}

function resultFor(finding: ApiFinding, ruleIndex: number): SarifResult {
  const result: SarifResult = {
    ruleId: finding.rule_id,
    ruleIndex,
    level: levelBySeverity[finding.severity],
    message: { text: resultMessage(finding) },
    properties: {
      aiCodeSecurityAnalyzerFindingId: finding.finding_id,
      originalSeverity: finding.severity,
      findingKind: finding.finding_kind,
      verificationStatus: finding.verification_status,
      evidenceValidationStatus: finding.evidence_validation_status,
      supportedClaims: [...finding.supported_claims],
      restrictedClaims: finding.restricted_claims.map((claim) => ({
        claimType: claim.claim_type,
        decision: claim.decision,
        reasonCodes: [...claim.reason_codes],
      })),
      validationErrorCode: finding.validation_error_code,
    },
  };
  const locations = locationFor(finding);
  if (locations) result.locations = locations;
  return result;
}

export function createSarifReport(context: ScanContext, input: ScanResponse): SarifReport {
  let scan: ScanResponse;
  try { scan = parseScan(input); } catch { throw new Error('sarif_scan_invalid'); }
  validateContext(context, scan);

  const findings = [...scan.findings].sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  const ruleIds = [...new Set(findings.map((finding) => finding.rule_id))].sort((left, right) => left.localeCompare(right));
  const firstByRule = new Map<string, ApiFinding>();
  for (const finding of findings) if (!firstByRule.has(finding.rule_id)) firstByRule.set(finding.rule_id, finding);
  const rules = ruleIds.map((ruleId) => ruleFor(ruleId, firstByRule.get(ruleId)!));
  const ruleIndexes = new Map(rules.map((rule, index) => [rule.id, index]));

  return {
    $schema: SARIF_SCHEMA_URI,
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'SAST Review Workspace',
        informationUri: 'https://github.com/misosos/sast-review-workspace',
        rules,
        properties: {
          detectionEngine: 'Semgrep',
          semgrepVersion: scan.semgrep_version,
          converterVersionAvailable: false,
        },
      } },
      invocations: [{ executionSuccessful: scan.scan_status === 'completed' && scan.completed }],
      results: findings.map((finding) => resultFor(finding, ruleIndexes.get(finding.rule_id)!)),
      properties: {
        targetId: context.targetId,
        targetLabel: context.targetLabel,
        ruleProfileId: context.ruleProfileId,
        ruleProfileLabel: context.ruleProfileLabel,
        experimental: context.experimental,
        scanStatus: scan.scan_status,
        completed: scan.completed,
        browserReceivedAt: new Date(context.receivedAt).toISOString(),
        findingCount: scan.finding_count,
        exportedFindingCount: scan.displayed_finding_count,
        omittedFindingCount: scan.omitted_finding_count,
        issues: [...scan.issues],
        limitations: [...scan.limitations],
        scopeNotice: 'Exported results are static-analysis findings, not confirmed vulnerabilities or proof of code safety.',
      },
    }],
  };
}

export function serializeSarifReport(report: SarifReport): string {
  const json = `${JSON.stringify(report, null, 2)}\n`;
  if (new TextEncoder().encode(json).byteLength > MAX_SARIF_BYTES) throw new Error('sarif_size_limit_exceeded');
  return json;
}

export function downloadSarifReport(report: SarifReport): void {
  const json = serializeSarifReport(report);
  const blob = new Blob([json], { type: SARIF_MIME_TYPE });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = SARIF_FILENAME;
  anchor.hidden = true;
  document.body.append(anchor);
  try { anchor.click(); }
  finally { anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
