import { readFileSync } from 'node:fs';
import Ajv from 'ajv-draft-04';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { createSarifReport } from '../src/features/scans/sarifExport';
import type { ScanContext } from '../src/features/scans/markdownExport';
import { createCodeScanningPreflight } from '../src/features/scans/codeScanningPreflight';

const schema = JSON.parse(readFileSync(`${process.cwd()}/tests/fixtures/sarif-schema-2.1.0.json`, 'utf8')) as object;
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateSchema = ajv.compile(schema);

const finding = (overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.javascript-dynamic-eval', severity: 'high',
  verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/hello world.js', line_number: 9,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null, ...overrides,
});

const makeScan = (findings: ApiFinding[] = [finding()], overrides: Partial<ScanResponse> = {}): ScanResponse => {
  const severity_counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((item) => { severity_counts[item.severity] += 1; });
  return {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length,
    displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts, issues: [], findings,
    limitations: ['finding_count_not_confirmed_vulnerability_count'], ...overrides,
  };
};

const context: ScanContext = {
  targetId: 'synthetic-project', targetLabel: 'Synthetic Project', ruleProfileId: 'baseline',
  ruleProfileLabel: 'Baseline Rules', experimental: false, scanStatus: 'completed', receivedAt: '2026-11-04T01:02:03.000Z',
};

const reportFor = (scan: ScanResponse, scanContext = context) => createSarifReport(scanContext, scan);

describe('GitHub Code Scanning SARIF preflight', () => {
  it('validates a generated report against the pinned OASIS schema but does not approve repository upload readiness', () => {
    const scan = makeScan();
    const report = reportFor(scan);
    expect(validateSchema(report), JSON.stringify(validateSchema.errors)).toBe(true);
    const result = createCodeScanningPreflight(scan, context, report);
    expect(result.checks.sarifStructure.status).toBe('VERIFIED');
    expect(result.checks.ruleReferences.status).toBe('VERIFIED');
    expect(result.checks.repositoryCommit.status).toBe('REQUIRES_VERIFICATION');
    expect(result.checks.fingerprints.status).toBe('UNSUPPORTED');
    expect(result.uploadReadiness).toBe('REQUIRES_VERIFICATION');
    expect(result.githubUploadPerformed).toBe(false);
  });

  it('blocks malformed SARIF and inconsistent rule references', () => {
    const scan = makeScan();
    const report = reportFor(scan);
    const malformed = createCodeScanningPreflight(scan, context, { ...report, version: '2.0.0' });
    expect(malformed.checks.sarifStructure.status).toBe('BLOCKED');
    expect(malformed.uploadReadiness).toBe('BLOCKED');
    const badIndex = structuredClone(report);
    badIndex.runs[0].results[0].ruleIndex = 99;
    const invalidReference = createCodeScanningPreflight(scan, context, badIndex);
    expect(invalidReference.checks.ruleReferences.status).toBe('BLOCKED');
  });

  it('checks stable rule descriptors and preserves unknown rule IDs without renaming', () => {
    const scan = makeScan([
      finding({ finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', rule_id: 'baseline.javascript-dynamic-eval' }),
      finding({ finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', rule_id: 'third_party.custom-rule' }),
    ]);
    const report = reportFor(scan);
    const result = createCodeScanningPreflight(scan, context, report);
    expect(result.checks.ruleReferences.status).toBe('VERIFIED');
    expect(result.checks.ruleStability.status).toBe('REQUIRES_VERIFICATION');
    expect(report.runs[0].tool.driver.rules.map((rule) => rule.id)).toEqual(['baseline.javascript-dynamic-eval', 'third_party.custom-rule']);
    expect(result.findingLocations).toHaveLength(2);
  });

  it('separates URI validity from remote repository and analyzed commit matching', () => {
    const scan = makeScan([finding({ file_path: 'src/안내 #?.js' })]);
    const report = reportFor(scan);
    const result = createCodeScanningPreflight(scan, context, report);
    expect(report.runs[0].results[0].locations?.[0].physicalLocation.artifactLocation.uri).toBe('src/%EC%95%88%EB%82%B4%20%23%3F.js');
    expect(result.findingLocations[0]).toMatchObject({ uriFormat: 'VERIFIED', repositoryFile: 'REQUIRES_VERIFICATION' });
    expect(result.checks.repositoryCommit.status).toBe('REQUIRES_VERIFICATION');
    expect(result.uploadReadiness).toBe('REQUIRES_VERIFICATION');
  });

  it.each([
    [finding({ file_path: null, line_number: null }), 'NO_FILE_OR_LINE'],
    [finding({ file_path: 'src/a.js', line_number: null }), 'FILE_WITHOUT_LINE'],
    [finding({ file_path: 'src/a.js', line_number: 9 }), 'FILE_AND_LINE'],
  ] as const)('reports the available source location state without inventing one', (item, locationState) => {
    const scan = makeScan([item]);
    const result = createCodeScanningPreflight(scan, context, reportFor(scan));
    expect(result.findingLocations[0].state).toBe(locationState);
    if (locationState === 'NO_FILE_OR_LINE') {
      expect(reportFor(scan).runs[0].results[0]).not.toHaveProperty('locations');
      expect(result.findingLocations[0].uriFormat).toBe('REQUIRES_VERIFICATION');
    }
  });

  it('does not treat Finding IDs as fingerprints and distinguishes upload mechanisms', () => {
    const scan = makeScan();
    const report = reportFor(scan);
    const result = createCodeScanningPreflight(scan, context, report);
    expect(result.checks.fingerprints.status).toBe('UNSUPPORTED');
    expect(result.uploadMethods).toMatchObject({
      uploadSarifAction: 'REQUIRES_VERIFICATION', restApi: 'REQUIRES_VERIFICATION',
    });
    expect(report.runs[0].results[0].properties.aiCodeSecurityAnalyzerFindingId).toBe(finding().finding_id);
    expect(report.runs[0].results[0]).not.toHaveProperty('partialFingerprints');
    expect(report.runs[0].results[0]).not.toHaveProperty('fingerprints');
  });

  it.each([
    ['completed', 0, 'VERIFIED'], ['completed', 2, 'BLOCKED'], ['partial', 0, 'BLOCKED'], ['timed_out', 0, 'BLOCKED'],
  ] as const)('treats %s scan with omitted=%s as scope status %s', (scanStatus, omitted, expectedStatus) => {
    const visible = [finding()];
    const scan = makeScan(visible, {
      scan_status: scanStatus, completed: scanStatus === 'completed', finding_count: 1 + omitted,
      displayed_finding_count: 1, omitted_finding_count: omitted,
      severity_counts: { critical: 0, high: 1 + omitted, medium: 0, low: 0, info: 0 },
      issues: omitted ? ['findings_omitted'] : [],
      limitations: scanStatus === 'completed' && !omitted ? [] : [omitted ? 'omitted_findings_not_individually_validated' : 'scan_failed'],
    });
    const scanContext = { ...context, scanStatus };
    const result = createCodeScanningPreflight(scan, scanContext, reportFor(scan, scanContext));
    expect(result.checks.scanScope.status).toBe(expectedStatus);
    expect(result.uploadReadiness).toBe(expectedStatus === 'BLOCKED' ? 'BLOCKED' : 'REQUIRES_VERIFICATION');
    expect(result.resultCount).toBe(1);
    expect(result.omittedFindingCount).toBe(omitted);
  });

  it('marks a zero-Finding completed scan as represented, not as proof of safety', () => {
    const scan = makeScan([]);
    const result = createCodeScanningPreflight(scan, context, reportFor(scan));
    expect(result.checks.scanScope.status).toBe('VERIFIED');
    expect(result.scopeMessage).toMatch(/안전성|안전/);
    expect(result.uploadReadiness).toBe('REQUIRES_VERIFICATION');
  });

  it('rejects response/context mismatches and remains deterministic without mutating inputs or making requests', () => {
    const scan = makeScan();
    const report = reportFor(scan);
    const beforeScan = structuredClone(scan);
    const beforeReport = structuredClone(report);
    const first = createCodeScanningPreflight(scan, context, report);
    const second = createCodeScanningPreflight(scan, context, report);
    expect(first).toEqual(second);
    expect(scan).toEqual(beforeScan);
    expect(report).toEqual(beforeReport);
    expect(createCodeScanningPreflight(scan, { ...context, targetId: 'other' }, report).uploadReadiness).toBe('BLOCKED');
  });

  it('reports no remote repository identity or commit proof from local target metadata', () => {
    const scan = makeScan();
    const result = createCodeScanningPreflight(scan, context, reportFor(scan));
    expect(result.checks.remoteRepository.status).toBe('REQUIRES_VERIFICATION');
    expect(result.checks.repositoryCommit.status).toBe('REQUIRES_VERIFICATION');
    expect(result.checks.sourceSnapshot.status).toBe('REQUIRES_VERIFICATION');
  });
});
