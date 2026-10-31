import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const assets = resolve(process.cwd(), '../docs/assets/ui-d5a-r');

test('D5A-R page headers stack and align with content at narrower viewports', async ({ page }) => {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'synthetic', label: '합성 프로젝트' }], rule_profiles: [{ id: 'baseline', label: '기본 규칙', experimental: false }] } }));
  await mkdir(assets, { recursive: true });

  const viewports = [
    { width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1024, height: 768 },
    { width: 768, height: 1024 }, { width: 600, height: 800 }, { width: 390, height: 844 }, { width: 320, height: 800 },
  ];
  for (const viewport of viewports) {
    const { width } = viewport;
    await page.setViewportSize(viewport);
    await page.goto('/');
    await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
    const startMetrics = await page.evaluate(() => {
      const box = (selector: string) => {
        const element = document.querySelector(selector);
        if (!element) throw new Error(`missing ${selector}`);
        const rect = element.getBoundingClientRect();
        return { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) };
      };
      return { heading: box('.workspace-title h1'), description: box('.workspace-title > p'), content: box('.mission-deck'), titleLayout: getComputedStyle(document.querySelector('.workspace-title')!).flexDirection, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth };
    });
    console.log('[D5A-R after start]', JSON.stringify({ viewport, ...startMetrics }));
    expect(startMetrics.overflow, `${width}px horizontal overflow`).toBeLessThanOrEqual(0);
    expect(startMetrics.heading.x).toBe(startMetrics.content.x);
    if (width <= 1100) {
      expect(startMetrics.description.x).toBe(startMetrics.heading.x);
      expect(startMetrics.description.y).toBeGreaterThan(startMetrics.heading.y);
      expect(startMetrics.titleLayout).toBe('column');
    } else {
      expect(startMetrics.titleLayout).not.toBe('column');
      expect(startMetrics.description.x).toBeGreaterThan(startMetrics.heading.x);
    }
    await page.screenshot({ path: resolve(assets, `after-start-${width}.png`), fullPage: true, animations: 'disabled' });

    if (width <= 760) {
      const menu = page.getByRole('button', { name: '내비게이션 열기' });
      await menu.click();
      await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(menu).toBeFocused();
    }

    for (const view of [{ label: '검사 결과', title: '검사 결과', selector: '.results-empty-state' }, { label: '사용 안내', title: '사용 안내', selector: '.guide-workspace' }]) {
      if (width <= 760) {
        await page.getByRole('button', { name: '내비게이션 열기' }).click();
        await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: view.label }).click();
      } else {
        await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: view.label }).click();
      }
      await expect(page.getByRole('heading', { name: view.title, exact: true })).toBeVisible();
      const metrics = await page.evaluate((selector) => {
        const rect = (element: Element) => {
          const box = element.getBoundingClientRect();
          return { x: Math.round(box.x), y: Math.round(box.y), width: Math.round(box.width), height: Math.round(box.height) };
        };
        const header = document.querySelector('.workspace-title');
        const content = document.querySelector(selector);
        const heading = header?.querySelector('h1');
        const description = header?.querySelector(':scope > p');
        if (!header || !content || !heading || !description) throw new Error('page heading measurement elements missing');
        return { heading: rect(heading), description: rect(description), content: rect(content), titleLayout: getComputedStyle(header).flexDirection, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth };
      }, view.selector);
      console.log('[D5A-R after page]', JSON.stringify({ viewport, page: view.label, ...metrics }));
      expect(metrics.overflow, `${width}px ${view.label} horizontal overflow`).toBeLessThanOrEqual(0);
      if (width <= 1100) {
        expect(metrics.description.x).toBe(metrics.heading.x);
        expect(metrics.description.y).toBeGreaterThan(metrics.heading.y);
        expect(metrics.heading.x).toBe(metrics.content.x);
      }
      if ([1024, 600, 390].includes(width)) await page.screenshot({ path: resolve(assets, `after-${view.label === '검사 결과' ? 'results' : 'guide'}-${width}.png`), fullPage: true, animations: 'disabled' });
    }
  }
});
