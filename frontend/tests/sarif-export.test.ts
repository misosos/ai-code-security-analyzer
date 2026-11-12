import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import Ajv from 'ajv-draft-04';
import addFormats from 'ajv-formats';
import { describe, expect, it, vi } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import type { ScanContext } from '../src/features/scans/markdownExport';
import {
  createSarifReport,
  downloadSarifReport,
  MAX_SARIF_BYTES,
  SARIF_FILENAME,
  serializeSarifReport,
} from '../src/features/scans/sarifExport';

const schemaText = readFileSync(`${process.cwd()}/tests/fixtures/sarif-schema-2.1.0.json`, 'utf8');
const schema = JSON.parse(schemaText) as object;
const schemaSha256 = createHash('sha256').update(schemaText).digest('hex');
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateSarif = ajv.compile(schema);

const finding = (overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: 'semgrep:0123456789abcdef01234567',
  rule_id: 'baseline.javascript-dynamic-eval',
  severity: 'high',
  verification_status: 'unverified',
  finding_kind: 'pattern',
  file_path: 'src/review file#1?.js',
  line_number: 12,
  evidence_validation_status: 'validated',
  supported_claims: ['match_reported', 'match_location_observed'],
  restricted_claims: [{
    claim_type: 'vulnerability_confirmed',
    decision: 'unsupported_claim',
    reason_codes: ['independent_confirmation_required'],
  }],
  validation_error_code: null,
  ...overrides,
});

const scan = (findings: ApiFinding[] = [finding()], overrides: Partial<ScanResponse> = {}): ScanResponse => {
  const severity_counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((item) => { severity_counts[item.severity] += 1; });
  return {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
    finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0,
    severity_counts, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'],
    ...overrides,
  };
};

const context: ScanContext = {
  targetId: 'synthetic-project', targetLabel: 'Synthetic Project',
  ruleProfileId: 'baseline', ruleProfileLabel: 'Baseline Rules', experimental: false,
  scanStatus: 'completed', receivedAt: '2026-11-04T01:02:03.000Z',
};

describe('SARIF 2.1.0 export', () => {
  it('pins and validates against the official OASIS Errata 01 schema', () => {
    expect(schemaSha256).toBe('c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e');
    const report = createSarifReport(context, scan());
    expect(validateSarif(report), JSON.stringify(validateSarif.errors)).toBe(true);
    expect(report.version).toBe('2.1.0');
    expect(report.$schema).toContain('docs.oasis-open.org/sarif/sarif/v2.1.0/errata01');
    expect(report.runs).toHaveLength(1);
  });

  it('identifies the converter and detection engine without inventing an analyzer version', () => {
    const run = createSarifReport(context, scan()).runs[0];
    expect(run.tool.driver.name).toBe('SAST Review Workspace');
    expect(run.tool.driver).not.toHaveProperty('version');
    expect(run.tool.driver).not.toHaveProperty('semanticVersion');
    expect(run.tool.driver.properties).toMatchObject({ detectionEngine: 'Semgrep', semgrepVersion: '1.182.1' });
  });

  it('deduplicates sorted rule descriptors and keeps rule references consistent', () => {
    const findings = [
      finding({ finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', rule_id: 'unknown.rule', file_path: 'b.js' }),
      finding({ finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', file_path: 'a.js' }),
      finding({ finding_id: 'semgrep:cccccccccccccccccccccccc', file_path: 'c.js' }),
    ];
    const run = createSarifReport(context, scan(findings)).runs[0];
    expect(run.tool.driver.rules.map((rule) => rule.id)).toEqual(['baseline.javascript-dynamic-eval', 'unknown.rule']);
    expect(run.results.map((result) => result.properties.aiCodeSecurityAnalyzerFindingId)).toEqual([
      'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', 'semgrep:cccccccccccccccccccccccc',
    ]);
    run.results.forEach((result) => {
      expect(run.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
    });
  });

  it.each([
    ['critical', 'error'], ['high', 'error'], ['medium', 'warning'], ['low', 'note'], ['info', 'note'],
  ] as const)('maps %s to %s and retains the original severity', (severity, level) => {
    const result = createSarifReport(context, scan([finding({ severity })])).runs[0].results[0];
    expect(result.level).toBe(level);
    expect(result.properties.originalSeverity).toBe(severity);
    expect(result.properties.verificationStatus).toBe('unverified');
  });

  it('retains validated, rejected and unavailable evidence states and exact claims per Finding', () => {
    const findings = [
      finding(),
      finding({ finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', evidence_validation_status: 'rejected', supported_claims: [], validation_error_code: 'evidence_unavailable' }),
      finding({ finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', evidence_validation_status: 'unavailable', supported_claims: [] }),
    ];
    const results = createSarifReport(context, scan(findings)).runs[0].results;
    expect(results.map((result) => result.properties.evidenceValidationStatus)).toEqual(['validated', 'rejected', 'unavailable']);
    const validated = results.find((item) => item.properties.evidenceValidationStatus === 'validated')!;
    expect(validated.properties.supportedClaims).toEqual(['match_reported', 'match_location_observed']);
    expect(validated.properties.restrictedClaims).toEqual([{
      claimType: 'vulnerability_confirmed', decision: 'unsupported_claim', reasonCodes: ['independent_confirmation_required'],
    }]);
  });

  it('encodes a safe relative URI and uses only an available positive startLine', () => {
    const result = createSarifReport(context, scan()).runs[0].results[0];
    expect(result.locations).toEqual([{ physicalLocation: {
      artifactLocation: { uri: 'src/review%20file%231%3F.js' }, region: { startLine: 12 },
    } }]);
    const pathOnly = createSarifReport(context, scan([finding({ line_number: null })])).runs[0].results[0];
    expect(pathOnly.locations).toEqual([{ physicalLocation: { artifactLocation: { uri: 'src/review%20file%231%3F.js' } } }]);
    const noPath = createSarifReport(context, scan([finding({ file_path: null, line_number: 99 })])).runs[0].results[0];
    expect(noPath).not.toHaveProperty('locations');
  });

  it('rejects invalid API/context data instead of creating locations or leaking extra fields', () => {
    expect(() => createSarifReport(context, scan([finding({ file_path: '/private/source.js' })]))).toThrow('sarif_scan_invalid');
    expect(() => createSarifReport({ ...context, scanStatus: 'partial' }, scan())).toThrow('sarif_context_mismatch');
    expect(() => createSarifReport(context, { ...scan(), api_token: 'secret-canary' } as unknown as ScanResponse)).toThrow('sarif_scan_invalid');
    expect(() => createSarifReport(context, scan([{ ...finding(), source_code: 'raw source canary' } as ApiFinding]))).toThrow('sarif_scan_invalid');
  });

  it('does not invent fingerprints, flows, source/sink locations, related locations or fixes', () => {
    const result = createSarifReport(context, scan()).runs[0].results[0];
    for (const key of ['partialFingerprints', 'fingerprints', 'codeFlows', 'relatedLocations', 'fixes']) {
      expect(result).not.toHaveProperty(key);
    }
    expect(JSON.stringify(result)).not.toContain('threadFlows');
    expect(JSON.stringify(result)).not.toContain('sourceLocation');
    expect(JSON.stringify(result)).not.toContain('sinkLocation');
  });

  it.each([
    ['completed', true, true], ['partial', false, false], ['timed_out', false, false],
  ] as const)('preserves %s scope and invocation success=%s', (scanStatus, completed, executionSuccessful) => {
    const response = scan([], {
      scan_status: scanStatus, completed, limitations: completed ? [] : [scanStatus === 'partial' ? 'scan_partial' : 'scan_failed'],
    });
    const report = createSarifReport({ ...context, scanStatus }, response);
    expect(report.runs[0].invocations).toEqual([{ executionSuccessful }]);
    expect(report.runs[0].properties.scanStatus).toBe(scanStatus);
    expect(report.runs[0].results).toEqual([]);
    expect(validateSarif(report), JSON.stringify(validateSarif.errors)).toBe(true);
  });

  it('preserves displayed and omitted counts without silently manufacturing results', () => {
    const response = scan([finding()], {
      finding_count: 3, displayed_finding_count: 1, omitted_finding_count: 2,
      severity_counts: { critical: 0, high: 3, medium: 0, low: 0, info: 0 },
      issues: ['findings_omitted'], limitations: ['omitted_findings_not_individually_validated'],
    });
    const run = createSarifReport(context, response).runs[0];
    expect(run.results).toHaveLength(1);
    expect(run.properties).toMatchObject({ findingCount: 3, exportedFindingCount: 1, omittedFindingCount: 2 });
  });

  it('is deterministic without mutating input arrays', () => {
    const first = finding({ finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', file_path: 'a.js' });
    const second = finding({ finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', file_path: 'b.js' });
    const input = scan([second, first]);
    const before = structuredClone(input);
    expect(serializeSarifReport(createSarifReport(context, input))).toBe(
      serializeSarifReport(createSarifReport(context, { ...input, findings: [first, second] })),
    );
    expect(input).toEqual(before);
  });

  it('enforces the UTF-8 cap and creates a fixed-name local download with URL cleanup', () => {
    const report = createSarifReport(context, scan());
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:sarif-test');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    vi.useFakeTimers();
    downloadSarifReport(report);
    expect(create).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(SARIF_FILENAME).toBe('ai-code-security-results.sarif');
    expect(document.querySelector('a[download]')).toBeNull();
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith('blob:sarif-test');
    vi.useRealTimers();

    const huge = structuredClone(report);
    huge.runs[0].properties.syntheticTestPadding = '가'.repeat(MAX_SARIF_BYTES);
    expect(() => serializeSarifReport(huge)).toThrow('sarif_size_limit_exceeded');
    expect(() => downloadSarifReport(huge)).toThrow('sarif_size_limit_exceeded');
  });
});
