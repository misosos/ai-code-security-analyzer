import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const scanResponse = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 2,
  displayed_finding_count: 2, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
  issues: [], limitations: ['scan_result_is_not_safety_proof'],
  findings: [
    { finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/routes/review.js', line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
    { finding_id: 'semgrep:1123456789abcdef01234567', rule_id: 'synthetic.html-example', severity: 'medium', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/ui/Notice.tsx', line_number: 28, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
  ],
};

async function stubApi(page: import('@playwright/test').Page, { failHealth = false } = {}) {
  if (failHealth) {
    await page.route('**/api/v1/health', (route) => route.abort());
    await page.route('**/api/v1/options', (route) => route.abort());
    return;
  }
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: 'Synthetic Review Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scanResponse }));
}

test('UI-D2 start screen follows Option B control rhythm and keeps required typography readable', async ({ page }) => {
  await stubApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await expect(page.getByLabel('검사 대상')).toBeVisible();
  await expect(page.getByLabel('검사 규칙 모음')).toBeVisible();
  await expect(page.getByLabel('로컬 API 토큰')).toBeVisible();
  await expect(page.getByRole('button', { name: '검사 실행' })).toBeDisabled();
  await expect(page.getByText('검사 흐름', { exact: true })).toBeVisible();
  const sizes = await page.evaluate(() => Object.fromEntries([
    ['title', '.workspace-title h1'], ['body', '.workspace-title > p'], ['sidebar', '.nav-item'],
    ['label', '.mission-control .control-label'], ['select', '#main-content select[aria-label="검사 대상"]'],
    ['button', '.launch-action'], ['help', '.launch-brief-copy > p:last-child'],
  ].map(([key, selector]) => {
    const element = document.querySelector(selector);
    if (!element) throw new Error(`missing typography element: ${selector}`);
    const style = getComputedStyle(element);
    return [key, { fontSize: style.fontSize, lineHeight: style.lineHeight, height: Math.round(element.getBoundingClientRect().height) }];
  })));
  const startBoxes = await page.evaluate(() => Object.fromEntries(['.workspace-title','.mission-deck','.mission-form','.token-control-group','.d2-start-brief'].map((selector) => {
    const element = document.querySelector(selector);
    if (!element) throw new Error(`missing layout element: ${selector}`);
    const rect = element.getBoundingClientRect();
    return [selector, { top: Math.round(rect.top + scrollY), height: Math.round(rect.height) }];
  })));
  console.log('[UI-D2 start computed typography]', JSON.stringify({ sizes, boxes: startBoxes }));
  expect(Number.parseFloat(sizes.title.fontSize)).toBeGreaterThanOrEqual(36);
  expect(Number.parseFloat(sizes.body.fontSize)).toBeGreaterThanOrEqual(18);
  expect(Number.parseFloat(sizes.sidebar.fontSize)).toBeGreaterThanOrEqual(18);
  expect(Number.parseFloat(sizes.select.fontSize)).toBeGreaterThanOrEqual(18);
  expect(Number.parseFloat(sizes.button.fontSize)).toBeGreaterThanOrEqual(18);
  expect(sizes.select.height).toBeGreaterThanOrEqual(56);
  await mkdir(resolve(process.cwd(), '../docs/assets/ui-d2'), { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/start-1440x900.png'), clip: { x: 0, y: 0, width: 1440, height: 900 } });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/start-1920x1080.png'), clip: { x: 0, y: 0, width: 1920, height: 1080 } });
  for (const viewport of [{ width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `start screen horizontal overflow at ${viewport.width}px`).toBeLessThanOrEqual(0);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect.poll(() => page.locator('.workspace-sidebar').evaluate((element) => element.getBoundingClientRect().right)).toBeLessThan(0);
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/start-390x844.png'), clip: { x: 0, y: 0, width: 390, height: 844 } });
  await page.getByRole('button', { name: '내비게이션 열기' }).click();
  await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
  await expect.poll(() => page.locator('.workspace-sidebar').evaluate((element) => element.getBoundingClientRect().left)).toBe(0);
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/mobile-menu-390x844.png'), clip: { x: 0, y: 0, width: 390, height: 844 } });
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: '내비게이션 열기' })).toBeFocused();
  await page.getByRole('button', { name: '내비게이션 열기' }).click();
  await page.getByRole('button', { name: '사용 안내' }).click();
  await expect(page.getByRole('heading', { name: '처음 시작하기' })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/guide-1440x900.png'), clip: { x: 0, y: 0, width: 1440, height: 900 } });
});

test('UI-D2 result review remains grounded in API data and fits required desktop and mobile widths', async ({ page }) => {
  await stubApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await page.getByRole('button', { name: /검사 결과/ }).click();
  await expect(page.getByRole('heading', { name: '이 세션에는 검사 결과가 없습니다' })).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/empty-results-1440x900.png'), clip: { x: 0, y: 0, width: 1440, height: 900 } });
  await page.getByRole('button', { name: '검사 시작', exact: true }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-ui-d2-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '발견 항목' })).toContainText('2');
  await expect(page.getByLabel('Finding 목록')).toContainText('src/routes/review.js:12');
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('실제 취약점으로 확정되지 않았습니다');
  await page.getByLabel('파일 경로, 규칙 이름 또는 ID 검색').fill('Notice.tsx');
  await expect(page.getByLabel('Finding 목록')).toContainText('Notice.tsx');
  await expect(page.getByLabel('Finding 목록')).not.toContainText('review.js');
  await page.getByLabel('선택한 Finding 상세').scrollIntoViewIfNeeded();
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/finding-detail-1440x900.png'), clip: { x: 0, y: 0, width: 1440, height: 900 } });
  await page.getByLabel('파일 경로, 규칙 이름 또는 ID 검색').clear();
  const titleSize = await page.locator('.workspace-title h1').evaluate((element) => getComputedStyle(element).fontSize);
  const rowSize = await page.locator('.finding-row .row-main > strong').first().evaluate((element) => getComputedStyle(element).fontSize);
  expect(Number.parseFloat(titleSize)).toBeGreaterThanOrEqual(36);
  expect(Number.parseFloat(rowSize)).toBeGreaterThanOrEqual(18);
  const resultBoxes = await page.evaluate(() => Object.fromEntries(['.workspace-title','.scan-context','.context-copy','.context-actions','.export-note','.scan-banner','.beginner-summary','.limitations','.overview-grid','.overview-grid > *','.severity-counts','.findings-section','.results-heading','.filter-row','.results-layout','.finding-list','.finding-row','.detail-panel'].map((selector) => {
    const element = document.querySelector(selector);
    if (!element) return [selector, null];
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return [selector, { top: Math.round(rect.top + scrollY), height: Math.round(rect.height), minHeight: style.minHeight, display: style.display }];
  })));
  console.log('[UI-D2 result bounding boxes]', JSON.stringify(resultBoxes));
  await mkdir(resolve(process.cwd(), '../docs/assets/ui-d2'), { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/results-1440x900.png'), clip: { x: 0, y: 0, width: 1440, height: 900 } });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/results-1920x1080.png'), clip: { x: 0, y: 0, width: 1920, height: 1080 } });
  for (const viewport of [{ width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    if (viewport.width === 390) await expect.poll(() => page.locator('.workspace-sidebar').evaluate((element) => element.getBoundingClientRect().right)).toBeLessThan(0);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `horizontal overflow at ${viewport.width}px`).toBeLessThanOrEqual(0);
    if (viewport.width === 1280 || viewport.width === 768) {
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: resolve(process.cwd(), `../docs/assets/ui-d2/results-${viewport.width}x${viewport.height}.png`), clip: { x: 0, y: 0, width: viewport.width, height: viewport.height } });
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/results-390x844.png'), clip: { x: 0, y: 0, width: 390, height: 844 } });
});

test('UI-D2 displays the real API bootstrap failure instead of a synthetic connected state', async ({ page }) => {
  await stubApi(page, { failHealth: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('로컬 API에 연결할 수 없습니다');
  await expect(page.getByRole('button', { name: '다시 연결' })).toBeVisible();
  await mkdir(resolve(process.cwd(), '../docs/assets/ui-d2'), { recursive: true });
  await page.screenshot({ path: resolve(process.cwd(), '../docs/assets/ui-d2/api-error-1440x900.png'), clip: { x: 0, y: 0, width: 1440, height: 900 } });
});
