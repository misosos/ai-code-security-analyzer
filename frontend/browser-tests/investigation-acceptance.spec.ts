import { expect, test } from '@playwright/test';

const emptyScan = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
  finding_count: 0, displayed_finding_count: 0, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  issues: [], findings: [],
  limitations: ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'],
};
const finding = (hex: string, file: string) => ({
  finding_id: `semgrep:${hex}`,
  rule_id: 'baseline.javascript-dynamic-eval', severity: 'high', verification_status: 'unverified',
  finding_kind: 'pattern', file_path: file, line_number: 1, evidence_validation_status: 'validated',
  supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null,
});
const scanWith = (findings: ReturnType<typeof finding>[]) => ({
  ...emptyScan, finding_count: findings.length, displayed_finding_count: findings.length,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, findings,
});
const opaque = (letter: string) => letter.repeat(43);

async function bootstrap(page: import('@playwright/test').Page) {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Synthetic Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
}

test('regular zero-Finding workflow never calls v2 and never presents safety proof', async ({ page }) => {
  await bootstrap(page);
  let v1Calls = 0;
  let v2Calls = 0;
  await page.route('**/api/v1/scans', (route) => { v1Calls += 1; return route.fulfill({ json: emptyScan }); });
  await page.route('**/api/v2/**', (route) => { v2Calls += 1; return route.fulfill({ status: 500, json: { error: 'internal_unavailable' } }); });

  await page.goto('/');
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-acceptance-token');
  await expect(page.getByLabel('일반 검사')).toBeChecked();
  await page.getByRole('button', { name: '검사 실행' }).click();

  await expect(page.getByRole('heading', { name: '발견 항목이 없습니다' })).toBeVisible();
  await expect(page.getByText('검사되지 않은 문제까지 안전하다는 뜻은 아닙니다.')).toBeVisible();
  expect(v1Calls).toBe(1);
  expect(v2Calls).toBe(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

test('a delayed evaluation cannot survive baseline release or overwrite the current workflow', async ({ page }) => {
  await bootstrap(page);
  const itemA = finding('aaaaaaaaaaaaaaaaaaaaaaaa', 'src/a.js');
  const itemB = finding('bbbbbbbbbbbbbbbbbbbbbbbb', 'src/b.js');
  const responses = [scanWith([itemA, itemB]), scanWith([itemA])];
  let scanIndex = 0;
  let resolveEvaluation: (() => void) | undefined;
  const evaluationMayReturn = new Promise<void>((resolve) => { resolveEvaluation = resolve; });
  const releases: Array<Record<string, unknown>> = [];

  await page.route('**/api/v2/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v2/investigation-scans') {
      const index = scanIndex++;
      return route.fulfill({ json: { contract_version: 'investigation-scan/v1', run_handle: opaque(index === 0 ? 'A' : 'B'), scan: responses[index] } });
    }
    if (path === '/api/v2/investigations') return route.fulfill({ status: 201, json: { contract_version: 'investigation-session/v1', investigation_handle: opaque('S') } });
    if (path === '/api/v2/investigations/evaluate') {
      await evaluationMayReturn;
      return route.fulfill({ json: {
        contract_version: 'finding-disappearance-evaluation/v1', comparability: 'COMPARABLE', overall_assessment: 'EXPLANATION_SUPPORTED',
        findings: [
          { finding_id: itemA.finding_id, category: 'shared', path_observation: 'PATH_REPORTED_SCANNED', skip_hypothesis: 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' },
          { finding_id: itemB.finding_id, category: 'baselineOnly', path_observation: 'PATH_NOT_REPORTED', skip_hypothesis: 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' },
        ], limitation_codes: ['source_snapshot_not_collected', 'scan_result_is_not_safety_proof'],
      } });
    }
    if (path === '/api/v2/investigation-release') {
      releases.push(route.request().postDataJSON() as Record<string, unknown>);
      return route.fulfill({ status: 204, body: '' });
    }
    return route.fulfill({ status: 404, json: { error: 'invalid_request' } });
  });

  await page.goto('/');
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-acceptance-token');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();
  const panel = page.getByRole('region', { name: '소멸 근거 조사' });
  await panel.getByRole('button', { name: '소멸 근거 조사 실행' }).click();
  await expect(panel.getByRole('button', { name: '증거 평가 중' })).toBeDisabled();

  await page.getByRole('button', { name: '비교 기준 해제' }).click();
  resolveEvaluation?.();
  await expect(page.getByText('비교 기준을 해제했습니다. 현재 검사 결과와 분석가 검토 기록은 유지됩니다.')).toBeVisible();
  await expect(page.getByText('검사 절차 설명을 뒷받침하는 근거 있음')).toHaveCount(0);
  await expect.poll(() => releases.some((body) => body.kind === 'investigation' && body.handle === opaque('S'))).toBe(true);
});

test('rule bytes response must finish before the map and cannot revive it after baseline release', async ({ page }) => {
  await bootstrap(page);
  let scanIndex = 0;
  let resumeRule: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => { resumeRule = resolve; });
  await page.route('**/api/v2/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v2/investigation-scans/rule-bytes') return route.fulfill({ json: { contract_version: 'investigation-scan/v1', run_handle: opaque(scanIndex++ ? 'B' : 'A'), scan: emptyScan } });
    if (path === '/api/v2/investigations') return route.fulfill({ status: 201, json: { contract_version: 'investigation-session/v1', investigation_handle: opaque('S') } });
    if (path === '/api/v2/investigations/evaluate') return route.fulfill({ json: { contract_version: 'finding-disappearance-evaluation/v1', comparability: 'COMPARABLE', overall_assessment: 'UNDETERMINED', findings: [], limitation_codes: ['source_snapshot_not_collected'] } });
    if (path === '/api/v2/investigations/rule-bytes/evaluate') {
      await gate;
      return route.fulfill({ json: { contract_version: 'rule-bytes-comparison/v1', status: 'SAME_SELECTED_BYTES', limitation_codes: ['selected_rule_bytes_only', 'loaded_rule_identity_unverified'] } });
    }
    if (path === '/api/v2/investigation-release') return route.fulfill({ status: 204, body: '' });
    return route.fulfill({ status: 404, json: { error: 'invalid_request' } });
  });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-token');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByLabel('규칙 파일 동일성 증거 포함').check();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();
  const panel = page.getByRole('region', { name: '소멸 근거 조사' });
  await panel.getByRole('button', { name: '소멸 근거 조사 실행' }).click();
  await expect(panel).toContainText('규칙 바이트 비교 응답을 확인하고 있습니다.');
  await expect(page.getByRole('region', { name: 'Security Evidence Gap Map' })).toHaveCount(0);
  await page.getByRole('button', { name: '비교 기준 해제' }).click();
  resumeRule?.();
  await expect(page.getByText('비교 기준을 해제했습니다. 현재 검사 결과와 분석가 검토 기록은 유지됩니다.')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Security Evidence Gap Map' })).toHaveCount(0);
});

test('the conservative local display deadline removes the map and requires new scans', async ({ page }) => {
  await bootstrap(page);
  let scanIndex = 0;
  await page.route('**/api/v2/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v2/investigation-scans') return route.fulfill({ json: { contract_version: 'investigation-scan/v1', run_handle: opaque(scanIndex++ ? 'B' : 'A'), scan: emptyScan } });
    if (path === '/api/v2/investigations') return route.fulfill({ status: 201, json: { contract_version: 'investigation-session/v1', investigation_handle: opaque('S') } });
    if (path === '/api/v2/investigations/evaluate') return route.fulfill({ json: { contract_version: 'finding-disappearance-evaluation/v1', comparability: 'COMPARABLE', overall_assessment: 'UNDETERMINED', findings: [], limitation_codes: ['source_snapshot_not_collected'] } });
    if (path === '/api/v2/investigation-release') return route.fulfill({ status: 204, body: '' });
    return route.fulfill({ status: 404, json: { error: 'invalid_request' } });
  });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-token');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();
  await page.getByRole('region', { name: '소멸 근거 조사' }).getByRole('button', { name: '소멸 근거 조사 실행' }).click();
  const map = page.getByRole('region', { name: 'Security Evidence Gap Map' });
  await expect(map).toBeVisible();
  await page.evaluate(() => {
    const advanced = performance.now() + 900_001;
    Object.defineProperty(performance, 'now', { configurable: true, value: () => advanced });
    window.dispatchEvent(new Event('focus'));
  });
  await expect(map).toHaveCount(0);
  await expect(page.getByRole('region', { name: '소멸 근거 조사' }).getByRole('status')).toContainText('보수적인 표시 시간이 만료됐습니다');
});
