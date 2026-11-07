import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('부분 기준과 해제 통신 실패를 구분하고 Finding·메모는 유지하며 새로고침으로 초기화한다', async ({ page }) => {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Synthetic' }], rule_profiles: [{ id: 'baseline', label: 'Baseline', experimental: false }],
  } }));
  await page.route('**/api/v2/investigation-scans', (route) => route.fulfill({ json: {
    contract_version: 'investigation-scan/v1', run_handle: 'A'.repeat(43), scan: {
      scan_status: 'partial', completed: false, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: ['evidence_unavailable'], limitations: ['scan_result_is_not_safety_proof', 'scan_partial'],
      findings: [{ finding_id: `semgrep:${'a'.repeat(24)}`, rule_id: 'baseline.javascript-dynamic-eval', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'synthetic.js', line_number: 1,
        evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null }],
    },
  } }));
  await page.route('**/api/v2/investigation-release', (route) => route.fulfill({ status: 503, json: { error: 'internal_unavailable' } }));
  await page.goto('/');
  await expect(page.getByText('API 연결됨')).toBeVisible();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-followup-token');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByText('현재 응답에 서버 조사 증거가 연결됐습니다.')).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByLabel('분석가 메모').fill('합성 후속 검토 메모');
  await page.getByLabel('수동 검토 상태').selectOption('needs_followup');
  await page.getByRole('button', { name: '부분 조사 결과를 증거 기준으로 저장' }).click();
  await expect(page.locator('.comparison-blocked')).toContainText('정상 결과 비교는 불가');
  await expect(page.locator('.comparison-blocked')).not.toContainText('새 검사를 실행하면 결과 차이를 확인');
  const release = page.getByRole('button', { name: '조사 증거 해제' });
  await release.focus();
  await page.keyboard.press('Enter');
  const panel = page.getByRole('region', { name: '소멸 근거 조사' });
  await expect(panel.getByRole('alert')).toContainText('서버 증거 해제를 확인하지 못했습니다');
  await expect(panel.getByRole('button', { name: '소멸 근거 조사 실행' })).toBeDisabled();
  await expect(page.getByLabel('분석가 메모')).toHaveValue('합성 후속 검토 메모');
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('needs_followup');
  await page.getByRole('button', { name: '비교 기준 해제' }).click();
  await expect(page.locator('.comparison-blocked')).toContainText('비교 기준이 없습니다');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.reload();
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await expect(page.getByLabel('로컬 API 토큰')).toHaveValue('');
  await expect(page.getByLabel('분석가 메모')).toHaveCount(0);
});
