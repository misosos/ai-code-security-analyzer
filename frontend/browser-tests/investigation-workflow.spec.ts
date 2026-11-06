import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const finding = (hex: string, rule: string, file: string) => ({
  finding_id: `semgrep:${hex}`,
  rule_id: rule,
  severity: 'high',
  verification_status: 'unverified',
  finding_kind: 'pattern',
  file_path: file,
  line_number: 3,
  evidence_validation_status: 'validated',
  supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null,
});

const scan = (findings: ReturnType<typeof finding>[]) => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
  finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
  issues: [], limitations: ['scan_result_is_not_safety_proof'], findings,
});

const itemA = finding('aaaaaaaaaaaaaaaaaaaaaaaa', 'baseline.javascript-dynamic-eval', 'src/a.js');
const itemB = finding('bbbbbbbbbbbbbbbbbbbbbbbb', 'baseline.react-dangerous-html', 'src/b.js');
const itemC = finding('cccccccccccccccccccccccc', 'baseline.firestore-unconditional-write', 'src/c.js');
const itemD = finding('dddddddddddddddddddddddd', 'baseline.react-dangerous-html', 'src/d.js');
const opaque = (letter: string) => letter.repeat(43);

test('explicit investigation mode connects two exact runs, displays conservative evaluation, and releases handles', async ({ page }) => {
  const requests: { path: string; body?: Record<string, unknown>; url: string }[] = [];
  const scanResponses = [scan([itemA, itemB, itemD]), scan([itemA, itemC])];
  let scanIndex = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Synthetic Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => {
    requests.push({ path: '/api/v1/scans', url: route.request().url() });
    return route.fulfill({ json: scanResponses[scanIndex++] });
  });
  await page.route('**/api/v2/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const body = request.postDataJSON() as Record<string, unknown> | undefined;
    requests.push({ path, body, url: request.url() });
    if (path === '/api/v2/investigation-scans') {
      const run = scanResponses[scanIndex++];
      const handle = scanIndex === 1 ? opaque('A') : opaque('B');
      return route.fulfill({ json: { contract_version: 'investigation-scan/v1', run_handle: handle, scan: run } });
    }
    if (path === '/api/v2/investigations') return route.fulfill({ status: 201, json: { contract_version: 'investigation-session/v1', investigation_handle: opaque('S') } });
    if (path === '/api/v2/investigations/evaluate') return route.fulfill({ json: {
      contract_version: 'finding-disappearance-evaluation/v1',
      comparability: 'COMPARABLE', overall_assessment: 'UNDETERMINED',
      findings: [
        { finding_id: itemA.finding_id, category: 'shared', path_observation: 'PATH_REPORTED_SCANNED', skip_hypothesis: 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' },
        { finding_id: itemB.finding_id, category: 'baselineOnly', path_observation: 'PATH_NOT_REPORTED', skip_hypothesis: 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' },
        { finding_id: itemD.finding_id, category: 'baselineOnly', path_observation: 'PATH_NOT_REPORTED', skip_hypothesis: 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' },
        { finding_id: itemC.finding_id, category: 'currentOnly', path_observation: 'PATH_REPORTED_SCANNED', skip_hypothesis: null, source_snapshot_hypothesis: null, rule_identity_hypothesis: null },
      ],
      limitation_codes: ['source_snapshot_not_collected', 'scope_completeness_unverified', 'scan_result_is_not_safety_proof'],
    } });
    if (path === '/api/v2/investigation-release') return route.fulfill({ status: 204, body: '' });
    return route.fulfill({ status: 404, json: { error: 'invalid_request' } });
  });

  await page.goto('/');
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-browser-token');
  await page.getByText('소멸 근거 조사 선택').click();
  await expect(page.getByLabel('일반 검사')).toBeChecked();
  expect(requests.filter((item) => item.path.startsWith('/api/v2/'))).toHaveLength(0);
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByText('현재 응답에 서버 조사 증거가 연결됐습니다.')).toBeVisible();
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByText('현재 응답에 서버 조사 증거가 연결됐습니다.')).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();
  const panel = page.getByRole('region', { name: '소멸 근거 조사' });
  await panel.getByRole('button', { name: '소멸 근거 조사 실행' }).click();
  await expect(panel).toContainText('현재 증거로 판단 불가');
  await expect(panel).toContainText('Finding 미관찰은 취약점 수정이나 해결 완료의 증거가 아닙니다.');
  await expect(panel).toContainText('src/b.js:3');
  await expect(panel).toContainText('현재 수집된 검사 경로 목록에서 이 경로가 보고되지 않았습니다.');
  const gapMap = page.getByRole('region', { name: 'Security Evidence Gap Map' });
  await expect(gapMap).toContainText('규칙 바이트 비교를 요청하지 않았습니다.');
  await expect(gapMap).toContainText('취약점 해결 여부는 이 조사만으로 판정할 수 없습니다.');
  const baselineList = panel.getByRole('list', { name: '기준 검사에서만 관찰 Finding 목록' });
  await expect(baselineList.getByRole('listitem')).toHaveCount(2);
  await baselineList.getByRole('button', { name: /src\/d\.js/ }).click();
  await expect(panel).toContainText('src/d.js:3');
  await expect(panel).not.toContainText(/취약점이 해결|취약점이 제거|코드가 안전해짐/);

  const evaluationRequest = requests.find((item) => item.path === '/api/v2/investigations/evaluate');
  expect(evaluationRequest?.body).toEqual({ investigation_handle: opaque('S') });
  expect(requests.filter((item) => item.path === '/api/v2/investigations')).toHaveLength(1);
  expect(requests.filter((item) => item.path === '/api/v1/scans')).toHaveLength(0);
  for (const request of requests.filter((item) => item.path.startsWith('/api/v2/'))) {
    expect(request.url).not.toContain('A'.repeat(43));
    expect(request.url).not.toContain('B'.repeat(43));
    expect(request.url).not.toContain('S'.repeat(43));
  }
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);

  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations).toEqual([]);
  for (const width of [1920, 1440, 1024, 768, 600, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const metrics = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(metrics.scroll, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(metrics.client);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: '../docs/assets/er-c3d-investigation-results-1440.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '../docs/assets/er-c3d-investigation-results-390.png', fullPage: true });

  await page.getByRole('button', { name: '조사 증거 해제' }).click();
  await expect(gapMap).toHaveCount(0);
  await expect(panel.getByRole('status')).toContainText('조사 세션과 Run 증거의 해제를 요청했습니다');
  await expect.poll(() => requests.filter((item) => item.path === '/api/v2/investigation-release').length).toBe(3);
  const releaseBodies = requests.filter((item) => item.path === '/api/v2/investigation-release').map((item) => item.body);
  expect(releaseBodies[0]).toEqual({ kind: 'investigation', handle: opaque('S') });
  expect(releaseBodies.slice(1).map((body) => body?.handle).sort()).toEqual([opaque('A'), opaque('B')].sort());
});

test('unsupported deployment does not silently retry through the standard scan API', async ({ page }) => {
  let standardScanCalls = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Synthetic Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => { standardScanCalls += 1; return route.fulfill({ json: scan([]) }); });
  await page.route('**/api/v2/investigation-scans', (route) => route.fulfill({ status: 503, json: { error: 'unsupported_deployment' } }));
  await page.goto('/');
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-browser-token');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('alert')).toContainText('공식 단일 Worker 실행');
  expect(standardScanCalls).toBe(0);
});
