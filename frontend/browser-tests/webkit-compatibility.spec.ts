import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const evidenceDir = resolve(process.cwd(), '../docs/assets/phase8g');

const finding = {
  finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.javascript-dynamic-eval', severity: 'high',
  verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/synthetic-review.js', line_number: 12,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null,
};
const response = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'], findings: [finding],
};

async function setup(page: import('@playwright/test').Page) {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: 'Synthetic Review Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: response }));
}

test('WebKit: 검사, Finding 검토, Markdown/SARIF/JSON 내보내기와 JSON 미리보기', async ({ page }) => {
  let scanRequests = 0;
  await setup(page);
  await page.route('**/api/v1/scans', (route) => { scanRequests += 1; return route.fulfill({ json: response }); });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-webkit-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' }).click();
  await page.getByLabel('Finding 목록').getByRole('button').click();
  await page.getByLabel('수동 검토 상태').selectOption('needs_followup');
  await page.getByLabel('분석가 메모').fill('WebKit 합성 메모');
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('추가 확인 필요');

  await page.getByText('분석가 검토 기록 내보내기', { exact: true }).click();
  const reviewDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '분석가 검토 기록 내보내기' }).click();
  const reviewDownload = await reviewDownloadPromise;
  expect(reviewDownload.suggestedFilename()).toBe('ai-code-security-analyst-review.md');
  const markdown = await readFile(await reviewDownload.path() ?? '', 'utf8');
  expect(markdown).toContain('추가 확인 필요');
  expect(markdown).not.toContain('WebKit 합성 메모');

  await page.getByText('SARIF 내보내기', { exact: true }).click();
  const sarifDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'SARIF 다운로드' }).click();
  const sarifDownload = await sarifDownloadPromise;
  expect(sarifDownload.suggestedFilename()).toBe('ai-code-security-results.sarif');
  const sarifText = await readFile(await sarifDownload.path() ?? '', 'utf8');
  expect(JSON.parse(sarifText)).toMatchObject({ version: '2.1.0' });
  expect(sarifText).toContain(finding.finding_id);
  expect(sarifText).not.toContain('synthetic-webkit-token');

  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  const backupDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
  const backupDownload = await backupDownloadPromise;
  expect(backupDownload.suggestedFilename()).toBe('ai-code-security-analyst-review-backup.json');
  const backupText = await readFile(await backupDownload.path() ?? '', 'utf8');
  expect(backupText).not.toContain('WebKit 합성 메모');
  const backup = JSON.parse(backupText);
  await page.getByLabel('검토 기록 불러오기(JSON)').setInputFiles({ name: 'webkit-backup.json', mimeType: 'application/json', buffer: Buffer.from(backupText) });
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toBeVisible();
  await page.getByText('Finding별 기록 확인 (1)', { exact: true }).click();
  await page.getByLabel('검토 기록 복원 미리보기').getByRole('button', { name: '이 기록 적용' }).click();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue(backup.findings[0].review_status);
  expect(scanRequests).toBe(1);

  const viewportSizes = [1920, 1440, 1280, 1024, 768, 600, 390, 320];
  for (const width of viewportSizes) {
    await page.setViewportSize({ width, height: 900 });
    const { client, scroll } = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(scroll, `WebKit horizontal overflow at ${width}px`).toBeLessThanOrEqual(client);
  }
});

test('WebKit: 모바일 Drawer 메뉴 선택과 Escape 후 포커스 복귀', async ({ page }) => {
  await setup(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const menuButton = page.getByRole('button', { name: '내비게이션 열기' });
  await menuButton.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
  await expect(page.getByRole('button', { name: '검사 시작' })).toBeFocused();
  await mkdir(evidenceDir, { recursive: true });
  await page.screenshot({ path: resolve(evidenceDir, 'webkit-mobile-drawer-390.png') });
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: '주 메뉴' })).toHaveCount(0);
  await expect(menuButton).toBeFocused();
  const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
});
