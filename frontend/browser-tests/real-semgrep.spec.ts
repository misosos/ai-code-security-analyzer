import { expect, test } from '@playwright/test';

const canary = 'SYNTHETIC_BROWSER_CANARY_MUST_NOT_LEAK';

test('real Chromium to FastAPI to Semgrep evidence to user-triggered Markdown download', async ({ page }) => {
  test.setTimeout(90_000);
  const token = process.env.BROWSER_E2E_API_TOKEN;
  if (!token) throw new Error('real_browser_e2e_token_missing');
  const scanRequests: string[] = [];
  const scanAuthLocations: string[] = [];
  page.on('request', (request) => {
    if (request.url().endsWith('/api/v1/scans')) {
      scanRequests.push(request.method());
      scanAuthLocations.push(request.headers()['x-local-api-token'] === token && !request.url().includes(token) ? 'header-only' : 'invalid');
    }
    if (!request.url().startsWith(process.env.BROWSER_E2E_BASE_URL!)) throw new Error('unexpected_external_request');
  });

  const documentResponse = await page.goto('/');
  expect(documentResponse?.status()).toBe(200);
  expect(documentResponse?.headers()['cache-control']).toBe('no-store');
  expect(documentResponse?.headers()['x-content-type-options']).toBe('nosniff');
  expect(documentResponse?.headers()['referrer-policy']).toBe('no-referrer');
  expect(documentResponse?.headers()['content-security-policy']).toContain("default-src 'self'");
  await expect(page.getByText(/API 연결됨/)).toBeVisible();
  await expect(page.getByRole('option', { name: 'Experimental · Experimental Command Injection' })).toBeAttached();

  await page.getByLabel('로컬 API 토큰').fill(token);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.getByLabel('규칙 프로필').selectOption('command-injection-experimental');
  const scanResponsePromise = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans'));
  await page.getByRole('button', { name: '검사 실행' }).click();
  const scanResponse = await scanResponsePromise;
  expect(scanResponse.status()).toBe(200);
  const responseBody = await scanResponse.text();
  const payload = JSON.parse(responseBody) as {
    scan_status: string; semgrep_version: string; finding_count: number; displayed_finding_count: number;
    findings: Array<{ finding_id: string; rule_id: string; severity: string; verification_status: string; finding_kind: string; evidence_validation_status: string; supported_claims: string[]; restricted_claims: Array<{ claim_type: string; decision: string }> }>;
  };
  expect(payload.scan_status).toBe('completed');
  expect(payload.semgrep_version).toBe('1.182.1');
  expect(payload.finding_count).toBe(1);
  expect(payload.displayed_finding_count).toBe(1);
  const finding = payload.findings.find((item) => item.rule_id === 'experimental.javascript-command-injection-taint');
  expect(finding).toBeDefined();
  expect(finding?.finding_id).toMatch(/^semgrep:[a-f0-9]{24}$/);
  expect(finding?.severity).toBe('high');
  expect(finding?.verification_status).toBe('unverified');
  expect(finding?.finding_kind).toBe('taint');
  expect(finding?.evidence_validation_status).toBe('validated');
  expect(finding?.supported_claims).toEqual(expect.arrayContaining([
    'match_reported', 'taint_rule_match_reported', 'source_pattern_declared',
    'sink_pattern_declared', 'match_location_observed',
  ]));
  expect(finding?.supported_claims).toHaveLength(5);
  expect(finding?.restricted_claims.map((claim) => claim.claim_type)).toEqual(expect.arrayContaining([
    'source_location_identified', 'sink_argument_location_identified', 'flow_trace_available',
    'sanitizer_match_observed', 'sanitizer_effectiveness_verified', 'vulnerability_confirmed',
  ]));
  expect(responseBody).not.toContain(canary);
  expect(responseBody).not.toContain(token);
  await expect(page.locator('body')).not.toContainText(token);

  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByText('experimental.javascript-command-injection-taint').first()).toBeVisible();
  await expect(page.getByText('미검증 후보').first()).toBeVisible();
  await page.getByText('기술 근거와 제한 자세히 보기').click();
  await expect(page.getByText('신뢰된 taint 규칙 매치 보고')).toBeVisible();
  await expect(page.getByText(/실제 Source 위치 정보가 제공되지 않았습니다/)).toBeVisible();
  await expect(page.getByText(/Sink 인자 위치 정보가 제공되지 않았습니다/)).toBeVisible();
  await expect(page.getByText(/trace가 제공되지 않았습니다/)).toBeVisible();
  await expect(page.getByText('unverified', { exact: true })).toBeVisible();
  await expect(page.getByText(canary)).toHaveCount(0);

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '현재 검사 결과 내보내기' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('ai-code-security-ui-review-summary.md');
  const stream = await download.createReadStream();
  let markdown = '';
  for await (const chunk of stream!) markdown += chunk.toString('utf8');
  expect(markdown).toContain(finding!.finding_id);
  expect(markdown).toContain('experimental.javascript-command-injection-taint');
  expect(markdown).toContain('신뢰된 taint 규칙 매치 보고');
  expect(markdown).toContain('source&#x5F;location&#x5F;identified');
  expect(markdown).toContain('sink&#x5F;argument&#x5F;location&#x5F;identified');
  expect(markdown).toContain('flow&#x5F;trace&#x5F;available');
  expect(markdown).toContain('취약점 확정 문서가 아니며');
  expect(markdown).not.toContain(canary);
  expect(markdown).not.toContain(token);
  expect(markdown).not.toContain(process.cwd());
  expect(scanRequests).toEqual(['POST']);
  expect(scanAuthLocations).toEqual(['header-only']);
});
