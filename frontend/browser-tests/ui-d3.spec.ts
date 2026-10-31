import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const finding = {
  finding_id: 'semgrep:2123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high',
  verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/routes/review.js', line_number: 12,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null,
};
const complete = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1,
  displayed_finding_count: 1, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [],
  limitations: ['scan_result_is_not_safety_proof'], findings: [finding],
};

async function apiFixture(page: import('@playwright/test').Page, scanResponse = complete) {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: 'Synthetic Review Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scanResponse }));
}

const shots = resolve(process.cwd(), '../docs/assets/ui-d3');
async function capture(page: import('@playwright/test').Page, name: string) {
  await mkdir(shots, { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, name), fullPage: false });
}

test('UI-D3 start control alignment preserves approved type and dimensions', async ({ page }) => {
  await apiFixture(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await expect(page.getByRole('button', { name: '검사 실행' })).toBeDisabled();

  const metrics = await page.evaluate(() => {
    const get = (selector: string) => {
      const el = document.querySelector<HTMLElement>(selector);
      if (!el) throw new Error(`필수 UI 요소 누락: ${selector}`);
      const rect = el.getBoundingClientRect();
      const css = getComputedStyle(el);
      return { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height), fontSize: css.fontSize, lineHeight: css.lineHeight };
    };
    return {
      title: get('.workspace-title h1'), deck: get('.mission-deck'), form: get('.mission-form'),
      token: get('.token-control-group'), projectSelect: get('select[aria-label="검사 대상"]'),
      rulesSelect: get('select[aria-label="검사 규칙 모음"]'), run: get('.launch-action'),
      sidebar: get('.workspace-sidebar .nav-item'),
    };
  });
  const rowGap = await page.locator('.mission-form').evaluate((el) => Number.parseFloat(getComputedStyle(el).rowGap));
  const gapBetweenTokenAndAction = Math.abs((metrics.token.y + metrics.token.height) - (metrics.run.y + metrics.run.height));
  console.log('[UI-D3 1440 검사 시작 측정]', JSON.stringify({ ...metrics, rowGap, gapBetweenTokenAndAction }));
  expect(Number.parseFloat(metrics.title.fontSize)).toBeGreaterThanOrEqual(36);
  expect(Number.parseFloat(metrics.projectSelect.fontSize)).toBeGreaterThanOrEqual(18);
  expect(Number.parseFloat(metrics.rulesSelect.fontSize)).toBeGreaterThanOrEqual(18);
  expect(metrics.projectSelect.height).toBeGreaterThanOrEqual(58);
  expect(metrics.run.height).toBeGreaterThanOrEqual(54);
  expect(gapBetweenTokenAndAction).toBeLessThanOrEqual(8);
  await capture(page, 'start-1440x900.png');

  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `가로 넘침: 검사 시작 ${viewport.width}px`).toBeLessThanOrEqual(0);
    if (viewport.width === 1920) await capture(page, 'start-1920x1080.png');
    if (viewport.width === 390) {
      await expect.poll(() => page.locator('.workspace-sidebar').evaluate((el) => el.getBoundingClientRect().right)).toBeLessThan(0);
      await capture(page, 'mobile-start-390x844.png');
      await page.getByRole('button', { name: '내비게이션 열기' }).click();
      await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
      await capture(page, 'mobile-menu-390x844.png');
      await page.keyboard.press('Escape');
      await expect(page.getByRole('button', { name: '내비게이션 열기' })).toBeFocused();
    }
  }
});

test('UI-D3 result review preserves hierarchy and common actions at desktop and mobile widths', async ({ page }) => {
  await apiFixture(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-ui-d3-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('실제 취약점으로 확정되지 않았습니다');
  await capture(page, 'results-1440x900.png');
  await page.locator('.results-layout').evaluate((el) => el.scrollIntoView({ block: 'start' }));
  await page.locator('.finding-row').first().waitFor({ state: 'visible' });
  await page.locator('.detail-panel').screenshot({ path: resolve(shots, 'finding-detail-1440x900.png') });

  const values = await page.evaluate(() => {
    const selectors = ['.workspace-title h1', '.scan-state-copy h2', '.metric strong', '.finding-row .row-main > strong', '.detail-top h2', '.filter-row input'];
    return Object.fromEntries(selectors.map((selector) => {
      const el = document.querySelector<HTMLElement>(selector);
      if (!el) throw new Error(`결과 화면 측정 요소 누락: ${selector}`);
      const css = getComputedStyle(el);
      return [selector, { fontSize: css.fontSize, lineHeight: css.lineHeight, height: Math.round(el.getBoundingClientRect().height) }];
    }));
  });
  const resultLayout = await page.evaluate(() => Object.fromEntries(['.workspace-title', '.scan-context', '.scan-banner', '.beginner-summary', '.limitations', '.overview-grid', '.results-heading', '.results-title', '.filter-row', '.results-layout'].map((selector) => {
    const el = document.querySelector<HTMLElement>(selector);
    if (!el) return [selector, null];
    const box = el.getBoundingClientRect();
    const css = getComputedStyle(el);
    return [selector, { x: Math.round(box.x), y: Math.round(box.y), documentY: Math.round(box.y + window.scrollY), width: Math.round(box.width), height: Math.round(box.height), display: css.display, gridColumns: css.gridTemplateColumns }];
  })));
  console.log('[UI-D3 결과 화면 측정]', JSON.stringify({ values, resultLayout }));
  const titleBox = await page.locator('.results-title').boundingBox();
  const filterBox = await page.locator('.filter-row').boundingBox();
  const listBox = await page.locator('.results-layout').boundingBox();
  if (!titleBox || !filterBox || !listBox) throw new Error('결과 화면 레이아웃 측정 요소 누락');
  expect(Math.abs(titleBox.y - filterBox.y)).toBeLessThanOrEqual(4);
  const listDocumentY = listBox.y + await page.evaluate(() => window.scrollY);
  console.log('[UI-D3 결과 목록 첫 화면 위치]', listDocumentY);
  expect(listDocumentY).toBeLessThan(810);
  const firstRowDocumentY = await page.locator('.finding-row').first().evaluate((el) => Math.round(el.getBoundingClientRect().top + window.scrollY));
  expect(firstRowDocumentY).toBeLessThan(870);

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '현재 검사 결과 내보내기' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain('.md');

  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `가로 넘침: 결과 ${viewport.width}px`).toBeLessThanOrEqual(0);
    if (viewport.width === 1920) await capture(page, 'results-1920x1080.png');
    if (viewport.width === 390) {
      await expect.poll(() => page.locator('.workspace-sidebar').evaluate((el) => el.getBoundingClientRect().right)).toBeLessThan(0);
      await capture(page, 'mobile-results-390x844.png');
    }
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: '결과 지우기' }).click();
  await page.getByRole('button', { name: '검사 결과' }).click();
  await expect(page.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeVisible();
  await capture(page, 'empty-results-1440x900.png');
});

test('UI-D3 partial response remains explicitly partial', async ({ page }) => {
  await apiFixture(page, { ...complete, scan_status: 'partial', completed: false, limitations: ['scan_partial', 'scan_result_is_not_safety_proof'] });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-ui-d3-partial-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '부분 검사', exact: true })).toBeVisible();
  await capture(page, 'partial-results-1440x900.png');
});

test('UI-D3 zero findings and API failure remain clearly distinguished', async ({ page }) => {
  await apiFixture(page, { ...complete, finding_count: 0, displayed_finding_count: 0, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [] });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-ui-d3-empty-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '발견 항목이 없습니다' })).toBeVisible();
  await capture(page, 'zero-findings-1440x900.png');

  await page.route('**/api/v1/health', (route) => route.abort());
  await page.route('**/api/v1/options', (route) => route.abort());
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('로컬 API에 연결할 수 없습니다');
  await expect(page.getByRole('button', { name: '검사 실행' })).toBeDisabled();
  await capture(page, 'api-error-1440x900.png');
});
