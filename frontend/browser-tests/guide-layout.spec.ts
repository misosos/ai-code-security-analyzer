import { expect, test } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const output = resolve(process.cwd(), '../docs/assets/ui-d4c-r/after');

async function openGuide(page: import('@playwright/test').Page, width: number, height: number) {
  await page.setViewportSize({ width, height });
  await page.goto('/');
  if (width <= 760) await page.getByRole('button', { name: '내비게이션 열기' }).click();
  const nav = width <= 760 ? page.getByRole('dialog', { name: '주 메뉴' }) : page.getByRole('navigation', { name: '화면 이동' });
  await nav.getByRole('button', { name: '사용 안내' }).click();
  await expect(page.getByRole('heading', { name: '검사 방법' })).toBeVisible();
}

test('UI-D4C-R guide reads as one document and progressively reveals advanced help', async ({ page }) => {
  await mkdir(output, { recursive: true });
  const layoutMeasurements: Array<Record<string, unknown>> = [];
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: '합성 검수 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: '기본 보안 규칙', experimental: false }],
  } }));

  for (const viewport of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await openGuide(page, viewport.width, viewport.height);
    const guide = page.locator('.guide-workspace.guide-document');
    await expect(guide.locator('> .guide-method')).toBeVisible();
    await expect(guide.locator('> .guide-result-guide')).toBeVisible();
    await expect(guide.locator('> .guide-additional')).toBeVisible();
    await expect(guide.locator('.guide-steps > li')).toHaveCount(3);
    await expect(guide).toHaveCSS('grid-template-columns', /\d+px/);
    const metrics = await guide.evaluate((element) => {
      const rect = element.getBoundingClientRect();
      const body = element.querySelector('.guide-limit-list li')!;
      const summary = element.querySelector('.guide-disclosure summary')!;
      const box = (selector: string) => {
        const target = element.querySelector(selector)!.getBoundingClientRect();
        return { x: Math.round(target.x), y: Math.round(target.y), width: Math.round(target.width), height: Math.round(target.height) };
      };
      return {
        width: Math.round(rect.width),
        height: Math.round(rect.height),
        bodyFont: getComputedStyle(body).fontSize,
        bodyLineHeight: getComputedStyle(body).lineHeight,
        disclosureFont: getComputedStyle(summary).fontSize,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        method: box('.guide-method'),
        resultMeaning: box('.guide-result-guide'),
        additional: box('.guide-additional'),
      };
    });
    expect(metrics.width).toBeLessThanOrEqual(viewport.width);
    expect(metrics.overflow).toBe(0);
    expect(Number.parseFloat(metrics.bodyFont)).toBeGreaterThanOrEqual(18);
    expect(Number.parseFloat(metrics.disclosureFont)).toBeGreaterThanOrEqual(18);
    layoutMeasurements.push({ viewport, ...metrics });
    await expect(guide.getByText(/실제 취약점으로 확정된 것은 아닙니다/)).toBeVisible();
    await expect(guide.getByText(/안전성이 보장되는 것은 아닙니다/)).toBeVisible();
    await expect(guide.getByText(/새로고침하거나 창을 닫으면 복원되지 않습니다/)).toBeVisible();
    await expect(guide.locator('.advanced-setup')).not.toHaveAttribute('open');
    await expect(guide.locator('.glossary')).not.toHaveAttribute('open');
    await page.screenshot({ path: resolve(output, `guide-${viewport.width}x${viewport.height}.png`), animations: 'disabled' });
  }

  await openGuide(page, 1440, 900);
  const admin = page.locator('.advanced-setup');
  await admin.locator('summary').focus();
  await page.keyboard.press('Enter');
  await expect(admin).toHaveAttribute('open');
  await expect(admin).toContainText('AI_CODE_SECURITY_TARGETS');
  await admin.locator('summary').evaluate((element: HTMLElement) => element.blur());
  await page.screenshot({ path: resolve(output, 'guide-admin-expanded-1440x900.png'), animations: 'disabled', fullPage: true });
  await admin.locator('summary').press('Space');
  await expect(admin).not.toHaveAttribute('open');

  const glossary = page.locator('.glossary');
  await glossary.locator('summary').focus();
  await page.keyboard.press('Space');
  await expect(glossary).toHaveAttribute('open');
  await expect(glossary).toContainText('근거 연결 확인 (Validated Evidence)');
  await expect(glossary).toContainText('Trace가 없다고 데이터 흐름이 없다는 뜻은 아닙니다');
  await glossary.locator('summary').evaluate((element: HTMLElement) => element.blur());
  await page.screenshot({ path: resolve(output, 'guide-glossary-expanded-1440x900.png'), animations: 'disabled', fullPage: true });

  await openGuide(page, 390, 844);
  await expect(page.locator('.guide-steps')).toHaveCSS('grid-template-columns', /\d+px/);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
  await page.screenshot({ path: resolve(output, 'guide-390x844.png'), animations: 'disabled' });
  const mobileMetrics = await page.locator('.guide-document').evaluate((element) => ({
    width: Math.round(element.getBoundingClientRect().width),
    bodyFont: getComputedStyle(element.querySelector('.guide-limit-list li')!).fontSize,
    summaryHeight: Math.round(element.querySelector('.guide-disclosure summary')!.getBoundingClientRect().height),
  }));
  expect(mobileMetrics.width).toBeLessThanOrEqual(390);
  expect(Number.parseFloat(mobileMetrics.bodyFont)).toBeGreaterThanOrEqual(17);
  expect(mobileMetrics.summaryHeight).toBeGreaterThanOrEqual(48);
  layoutMeasurements.push({ viewport: { width: 390, height: 844 }, ...mobileMetrics });
  await writeFile(resolve(output, 'layout-measurements.json'), JSON.stringify(layoutMeasurements, null, 2));
});
