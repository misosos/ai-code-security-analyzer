import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv-draft-04';
import addFormats from 'ajv-formats';

const schema = JSON.parse(readFileSync(`${process.cwd()}/tests/fixtures/sarif-schema-2.1.0.json`, 'utf8')) as object;
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateSarif = ajv.compile(schema);

test('downloads schema-valid SARIF on an explicit click without another API request', async ({ page }) => {
  const token = 'synthetic-sarif-token';
  let scans = 0;
  const externalRequests: string[] = [];
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: 'Synthetic Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', async (route) => {
    scans += 1;
    expect(route.request().headers()['x-local-api-token']).toBe(token);
    await route.fulfill({ json: {
      scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
      finding_count: 3, displayed_finding_count: 3, omitted_finding_count: 0,
      severity_counts: { critical: 0, high: 2, medium: 1, low: 0, info: 0 }, issues: [],
      limitations: ['scan_result_is_not_safety_proof'],
      findings: [
        { finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.javascript-dynamic-eval', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/review file.js', line_number: 7, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
        { finding_id: 'semgrep:1123456789abcdef01234567', rule_id: 'baseline.react-dangerous-html', severity: 'medium', verification_status: 'unverified', finding_kind: 'pattern', file_path: null, line_number: null, evidence_validation_status: 'unavailable', supported_claims: [], restricted_claims: [{ claim_type: 'match_location_observed', decision: 'unavailable', reason_codes: ['match_location_unavailable'] }], validation_error_code: null },
        { finding_id: 'semgrep:2123456789abcdef01234567', rule_id: 'baseline.firestore-unconditional-write', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'firestore.rules', line_number: 4, evidence_validation_status: 'rejected', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'insufficient_evidence', reason_codes: ['independent_confirmation_required'] }], validation_error_code: 'evidence_location_mismatch' },
      ],
    } });
  });

  await page.goto('/');
  const appOrigin = new URL(page.url()).origin;
  page.on('request', (request) => { if (!request.url().startsWith(appOrigin)) externalRequests.push(request.url()); });
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'SARIF 다운로드' })).toHaveCount(0);
  await page.getByText('SARIF 내보내기', { exact: true }).click();
  await expect(page.getByText(/GitHub 자동 업로드를 수행하지 않습니다/)).toBeVisible();
  await page.getByText(/GitHub Code Scanning 연동 사전 확인/).click();
  await expect(page.getByText('원격 저장소 및 commit의 파일 일치')).toBeVisible();
  await expect(page.getByText(/업로드 준비 상태:/)).toContainText('REQUIRES_VERIFICATION');
  await expect(page.getByText('Finding ID는 GitHub fingerprint가 아닙니다.')).toBeVisible();
  const accessibility = await new AxeBuilder({ page }).include('.code-scanning-preflight').analyze();
  expect(accessibility.violations, JSON.stringify(accessibility.violations)).toEqual([]);

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'SARIF 다운로드' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('ai-code-security-results.sarif');
  const stream = await download.createReadStream();
  let json = '';
  for await (const chunk of stream!) json += chunk.toString('utf8');
  const report = JSON.parse(json) as Record<string, unknown>;
  expect(validateSarif(report), JSON.stringify(validateSarif.errors)).toBe(true);
  expect(json).toContain('baseline.javascript-dynamic-eval');
  expect(json).toContain('baseline.react-dangerous-html');
  expect(json).toContain('baseline.firestore-unconditional-write');
  expect(json).toContain('src/review%20file.js');
  expect(json).toContain('"level": "error"');
  expect(json).not.toContain(token);
  expect(json).not.toContain('partialFingerprints');
  expect(json).not.toContain('codeFlows');
  expect(scans).toBe(1);
  expect(externalRequests).toEqual([]);
  await expect(page.getByText(/SARIF 2\.1\.0 파일을 다운로드했습니다/)).toContainText('GitHub 업로드는 수행하지 않았습니다');
});
