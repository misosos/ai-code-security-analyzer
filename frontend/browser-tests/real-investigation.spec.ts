import { expect, test } from '@playwright/test';
import { writeFile } from 'node:fs/promises';

test('real investigation mode reports an ignored baseline finding while preserving partial status and bounded evidence', async ({ page }) => {
  test.setTimeout(120_000);
  const token = process.env.BROWSER_E2E_API_TOKEN;
  const targetPath = process.env.BROWSER_E2E_INVESTIGATION_PATH;
  if (!token || !targetPath) throw new Error('real_investigation_e2e_configuration_required');
  const requests: Array<{ path: string; url: string; body?: Record<string, unknown>; auth: boolean }> = [];
  const responses: Array<{ path: string; status: number; body?: Record<string, unknown> }> = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin !== process.env.BROWSER_E2E_BASE_URL) throw new Error('unexpected_external_request');
    if (url.pathname.startsWith('/api/v2/')) requests.push({
      path: url.pathname,
      url: request.url(),
      body: request.postDataJSON() as Record<string, unknown> | undefined,
      auth: request.headers()['x-local-api-token'] === token,
    });
  });
  page.on('response', async (response) => {
    const path = new URL(response.url()).pathname;
    if (!path.startsWith('/api/v2/')) return;
    try { responses.push({ path, status: response.status(), body: await response.json() as Record<string, unknown> }); }
    catch { responses.push({ path, status: response.status() }); }
  });

  await page.goto('/');
  await expect(page.getByText(/API 연결됨/)).toBeVisible();
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByLabel('검사 대상').selectOption('synthetic-investigation');
  await page.getByLabel('검사 규칙 모음').selectOption('baseline');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByLabel('규칙 파일 동일성 증거 포함').check();

  const firstRunResponse = page.waitForResponse((response) => response.url().endsWith('/api/v2/investigation-scans/rule-bytes'));
  await page.getByRole('button', { name: '검사 실행' }).click();
  const firstRun = await firstRunResponse;
  expect(firstRun.status()).toBe(200);
  const firstEnvelope = await firstRun.json() as { contract_version: string; run_handle: string; scan: { findings: Array<{ rule_id: string; file_path: string | null; finding_id: string }> } };
  expect(firstEnvelope.contract_version).toBe('investigation-scan/v1');
  expect(firstEnvelope.run_handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(firstEnvelope.scan.findings.map((item) => item.rule_id).sort()).toEqual(['baseline.javascript-dynamic-eval', 'baseline.javascript-dynamic-eval']);
  expect(firstEnvelope.scan.findings.map((item) => item.file_path)).toContain('retired.js');
  const retiredFindingId = firstEnvelope.scan.findings.find((item) => item.file_path?.endsWith('retired.js'))?.finding_id;
  const stableFindingId = firstEnvelope.scan.findings.find((item) => item.file_path?.endsWith('stable.js'))?.finding_id;
  expect(retiredFindingId).toBeTruthy();
  expect(stableFindingId).toBeTruthy();
  expect(firstEnvelope.scan.findings).toHaveLength(2);
  expect(JSON.stringify(firstEnvelope)).not.toContain(token);
  await expect(page.getByText('현재 응답에 서버 조사 증거가 연결됐습니다.')).toBeVisible();
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();

  await writeFile(`${targetPath}/.semgrepignore`, 'retired.js\n', { mode: 0o600 });
  await writeFile(`${targetPath}/added.js`, 'function added(input) { return eval(input); }\n', { mode: 0o600 });
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  const secondRunResponse = page.waitForResponse((response) => response.url().endsWith('/api/v2/investigation-scans/rule-bytes'));
  await page.getByRole('button', { name: '검사 실행' }).click();
  const secondRun = await secondRunResponse;
  expect(secondRun.status()).toBe(200);
  const secondEnvelope = await secondRun.json() as { run_handle: string; scan: { findings: Array<{ rule_id: string; file_path: string | null; finding_id: string }> } };
  expect(secondEnvelope.run_handle).not.toBe(firstEnvelope.run_handle);
  expect(secondEnvelope.scan).toMatchObject({ scan_status: 'partial', completed: false });
  expect(secondEnvelope.scan.findings.map((item) => item.rule_id).sort()).toEqual(['baseline.javascript-dynamic-eval', 'baseline.javascript-dynamic-eval']);
  expect(secondEnvelope.scan.findings.some((item) => item.finding_id === retiredFindingId)).toBe(false);
  const currentFindingIds = new Map(secondEnvelope.scan.findings.map((item) => [item.file_path, item.finding_id]));
  expect(currentFindingIds.get('stable.js')).toBe(stableFindingId);
  expect(currentFindingIds.has('added.js')).toBe(true);

  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();
  const panel = page.getByRole('region', { name: '소멸 근거 조사' });
  await expect(page.locator('.comparison-blocked')).toContainText('부분 검사 또는 실패한 결과는 비교할 수 없습니다.');
  await expect(page.getByText(/이 검사는 일부만 완료됐습니다/)).toBeVisible();
  await panel.getByRole('button', { name: '소멸 근거 조사 실행' }).click();
  await expect(panel).toContainText('평가가 완료됐습니다');
  await expect(panel).toContainText('양쪽 검사에서 관찰');
  await expect(panel).toContainText('기준 검사에서만 관찰');
  await expect(panel).toContainText('이번 검사에서만 관찰');
  await expect(panel).toContainText('신뢰 가능한 비교 불가');
  await panel.locator('.comparison-category-switch').getByRole('button', { name: /기준 검사에서만 관찰/ }).click();
  await expect(panel.locator('.investigation-finding-result h4')).toHaveText('기준 검사에서만 관찰');
  await expect(panel).toContainText('retired.js');
  await expect(panel).toContainText('현재 검사에서 해당 경로가 제외된 것으로 보고됐습니다.');
  await expect(panel).toContainText('해당 가설을 뒷받침하는 근거 관찰');
  await expect(panel).toContainText('Finding 미관찰은 취약점 수정이나 해결 완료의 증거가 아닙니다.');
  await expect(panel).toContainText('규칙 파일 바이트 비교');
  await expect(panel).toContainText('규칙 파일 바이트 비교 근거가 부족합니다.');
  await expect(panel).toContainText('Semgrep이 실제로 로딩한 모든 규칙이나 취약점 해결 여부는 확인되지 않았습니다.');
  const gapMap = page.getByRole('region', { name: 'Security Evidence Gap Map' });
  await expect(gapMap).toContainText('비교 불가');
  await expect(gapMap).toContainText('소스 스냅샷을 수집하지 않았습니다.');
  await expect(gapMap).toContainText('전체 로딩 규칙 동일성은 검증되지 않았습니다.');
  await expect(gapMap).toContainText('전체 검사 범위의 완전성은 검증되지 않았습니다.');
  await expect(gapMap).toContainText('취약점 해결 여부는 이 조사만으로 판정할 수 없습니다.');
  await gapMap.getByText(/기준 검사에서만 관찰된 Finding별 근거/).click();
  await expect(gapMap).toContainText('현재 검사에서 이 경로가 제외됐다고 보고됐습니다.');
  await expect(gapMap).toContainText('Ignore 설정 및 파일 포함 여부');

  const session = responses.find((item) => item.path === '/api/v2/investigations');
  const evaluation = responses.find((item) => item.path === '/api/v2/investigations/evaluate');
  const ruleBytesEvaluation = responses.find((item) => item.path === '/api/v2/investigations/rule-bytes/evaluate');
  expect(session?.status).toBe(201);
  expect(evaluation?.status).toBe(200);
  expect(ruleBytesEvaluation?.status).toBe(200);
  expect(ruleBytesEvaluation?.body).toEqual({
    contract_version: 'rule-bytes-comparison/v1',
    status: 'UNVERIFIED',
    limitation_codes: ['selected_rule_bytes_only', 'loaded_rule_identity_unverified'],
  });
  const evalPayload = evaluation?.body as { findings: Array<{ category: string; finding_id: string; path_observation: string | null; skip_hypothesis: string | null }>; overall_assessment: string };
  expect(evalPayload.overall_assessment).toBe('INCOMPARABLE');
  expect(evalPayload.findings.map((item) => item.category).sort()).toEqual(['baselineOnly', 'currentOnly', 'shared']);
  const baselineOnlyResult = evalPayload.findings.find((item) => item.category === 'baselineOnly');
  expect(baselineOnlyResult?.finding_id).toBe(retiredFindingId);
  expect(baselineOnlyResult?.path_observation).toBe('PATH_EXPLICITLY_SKIPPED');
  expect(baselineOnlyResult?.skip_hypothesis).toBe('SUPPORTED');
  expect(evalPayload.findings.find((item) => item.finding_id === stableFindingId)?.category).toBe('shared');
  expect(evalPayload.findings.find((item) => item.finding_id === currentFindingIds.get('added.js'))?.category).toBe('currentOnly');
  expect(requests.every((item) => item.auth)).toBe(true);
  expect(requests.every((item) => !item.url.includes(firstEnvelope.run_handle) && !item.url.includes(secondEnvelope.run_handle))).toBe(true);
  expect(requests.find((item) => item.path === '/api/v2/investigations')?.body).toEqual({ baseline_handle: firstEnvelope.run_handle, current_handle: secondEnvelope.run_handle });
  expect(requests.find((item) => item.path === '/api/v2/investigations/evaluate')?.body).toEqual({ investigation_handle: (session?.body as { investigation_handle: string }).investigation_handle });
  await expect(page.locator('body')).not.toContainText(token);
  await expect(page.locator('body')).not.toContainText(process.env.BROWSER_E2E_PRIVATE_PATH ?? '/private/');
  expect(JSON.stringify(evalPayload)).not.toContain('retired(input)');

  await panel.getByRole('button', { name: '조사 증거 해제' }).click();
  await expect(panel.getByRole('status')).toContainText('해제를 요청했습니다');
  await expect(gapMap).toHaveCount(0);
  await expect.poll(() => responses.filter((item) => item.path === '/api/v2/investigation-release').length).toBe(3);
  expect(responses.filter((item) => item.path === '/api/v2/investigation-release').every((item) => item.status === 204)).toBe(true);

  const investigationHandle = (session?.body as { investigation_handle: string }).investigation_handle;
  const unavailableAfterRelease = await page.evaluate(async ({ apiToken, handle }) => {
    const response = await fetch('/api/v2/investigations/evaluate', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Local-API-Token': apiToken },
      body: JSON.stringify({ investigation_handle: handle }), cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    return { status: response.status, body: await response.json() };
  }, { apiToken: token, handle: investigationHandle });
  expect(unavailableAfterRelease).toEqual({ status: 404, body: { error: 'evidence_unavailable' } });
});
