import { expect, test } from '@playwright/test';

test('browser loads dashboard, accepts token in memory, and displays validated evidence safely', async ({ page }) => {
  const token = 'browser-smoke-token-that-is-not-persisted';
  const filePath = 'src/<img src=x onerror=alert(1)>.js';
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Local Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }, { id: 'command-injection-experimental', label: 'Experimental Command Injection', experimental: true }],
  } }));
  await page.route('**/api/v1/scans', async (route) => {
    expect(route.request().headers()['x-local-api-token']).toBe(token);
    expect(route.request().url()).not.toContain(token);
    expect(route.request().postData() ?? '').not.toContain(token);
    await route.fulfill({ json: {
      scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
      findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'experimental.command-injection', severity: 'high', verification_status: 'unverified', finding_kind: 'taint', file_path: filePath, line_number: 7, evidence_validation_status: 'validated', supported_claims: ['match_reported','taint_rule_match_reported'], restricted_claims: [{ claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent'] }, { claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
    } });
  });

  await page.goto('/');
  await expect(page.getByText(/연결됨/)).toBeVisible();
  await expect(page.getByRole('option', { name: 'Experimental · Experimental Command Injection' })).toBeAttached();
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByText('신뢰된 taint 규칙 매치 보고')).toBeVisible();
  await expect(page.getByText(/trace가 제공되지 않았습니다/)).toBeVisible();
  await expect(page.getByRole('img')).toHaveCount(0);
  await expect(page.getByLabel('선택한 Finding 상세').getByText(`${filePath}:7`, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('mobile layout fits 320px and token controls are keyboard reachable', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 780 });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'local-project', label: 'Local Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.goto('/');
  await expect(page.getByLabel('로컬 API 토큰')).toBeVisible();
  const dimensions = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
  await page.getByLabel('로컬 API 토큰').fill('keyboard-smoke-token');
  await page.getByLabel('로컬 API 토큰').focus();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: '지우기' })).toBeFocused();
});

test('browser preserves scan context, downloads the current summary on click, and clears only in-memory results', async ({ page }) => {
  const token = 'browser-export-token-not-for-report';
  let scans = 0;
  const externalRequests: string[] = [];
  page.on('request', (request) => { if (!request.url().startsWith('http://127.0.0.1:4173')) externalRequests.push(request.url()); });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Local Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }, { id: 'command-injection-experimental', label: 'Experimental Command Injection', experimental: true }],
  } }));
  await page.route('**/api/v1/scans', async (route) => {
    scans += 1;
    expect(route.request().headers()['x-local-api-token']).toBe(token);
    await route.fulfill({ json: {
      scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
      findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.test-rule', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/check.js', line_number: 4, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
    } });
  });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('이 결과를 생성한 검사 설정')).toContainText('Baseline Rules');
  await page.getByLabel('규칙 프로필').selectOption('command-injection-experimental');
  await expect(page.getByRole('alert')).toContainText('이전 검사 설정(Local Project · Baseline Rules)');

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '현재 검사 결과 내보내기' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('ai-code-security-ui-review-summary.md');
  const stream = await download.createReadStream();
  let markdown = '';
  for await (const chunk of stream!) markdown += chunk.toString('utf8');
  expect(markdown).toContain('Baseline Rules');
  expect(markdown).toContain('Semgrep 규칙 매치 보고');
  expect(markdown).toContain('취약점 확정 문서가 아니며');
  expect(markdown).not.toContain('Experimental Command Injection (command-injection-experimental)');
  expect(markdown).not.toContain(token);
  expect(scans).toBe(1);
  expect(externalRequests).toEqual([]);

  await page.getByRole('button', { name: '결과 지우기' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toHaveCount(0);
  await expect(page.getByLabel('로컬 API 토큰')).toHaveValue(token);
  await page.reload();
  await expect(page.getByLabel('로컬 API 토큰')).toHaveValue('');
  await expect(page.getByText('검사 결과가 여기에 표시됩니다')).toBeVisible();
});
