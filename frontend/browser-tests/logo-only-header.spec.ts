import { expect, test } from '@playwright/test';

const readyOptions = {
  targets: [{ id: 'synthetic', label: '합성 UI 검수 대상' }],
  rule_profiles: [{ id: 'baseline', label: '기본 검사 규칙', experimental: false }],
};

test('logo-only header and consolidated sidebar status remain aligned at supported viewports', async ({ page }) => {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: readyOptions }));

  for (const viewport of [
    { width: 1920, height: 1080 },
    { width: 1440, height: 900 },
    { width: 1280, height: 800 },
    { width: 768, height: 1024 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport);
    await page.goto('/');
    const header = page.locator('.topbar');
    const logo = header.getByRole('link', { name: 'AI Code Security Analyzer' });
    const sidebarStatus = page.getByRole('status', { name: 'API 연결됨 · 검사 옵션 준비됨' });

    await expect(logo).toBeVisible();
    await expect(header.locator('.brand-copy, .header-status')).toHaveCount(0);
    await expect(sidebarStatus).toBeVisible();
    await expect(sidebarStatus.locator('.sidebar-status-copy')).toContainText('API 연결됨');
    await expect(sidebarStatus.locator('.sidebar-status-copy')).toContainText('검사 옵션 준비됨');

    const geometry = await page.evaluate(() => {
      const headerElement = document.querySelector('.topbar')!;
      const mark = document.querySelector('.brand-emblem')!;
      const sidebarStatusElement = document.querySelector('.sidebar-footnote')!;
      const title = document.querySelector('.workspace-title h1')!;
      const headerRect = headerElement.getBoundingClientRect();
      const markRect = mark.getBoundingClientRect();
      const statusRect = sidebarStatusElement.getBoundingClientRect();
      const titleRect = title.getBoundingClientRect();
      return {
        viewport: `${innerWidth}x${innerHeight}`,
        headerHeight: headerRect.height,
        markCenterY: markRect.y + markRect.height / 2,
        headerCenterY: headerRect.y + headerRect.height / 2,
        sidebarStatusBottom: statusRect.bottom,
        titleTop: titleRect.top,
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: document.documentElement.clientWidth,
      };
    });
    expect(geometry.headerHeight).toBe(64);
    expect(Math.abs(geometry.markCenterY - geometry.headerCenterY)).toBeLessThanOrEqual(1);
    expect(geometry.sidebarStatusBottom).toBeGreaterThan(geometry.headerHeight);
    expect(geometry.titleTop).toBeGreaterThanOrEqual(geometry.headerHeight);
    expect(geometry.documentWidth).toBeLessThanOrEqual(geometry.viewportWidth);
    console.log('[UI-D4C-H geometry]', JSON.stringify(geometry));

    if (viewport.width > 760) {
      await page.getByRole('button', { name: '사이드바 접기' }).click();
      await expect(sidebarStatus).toHaveAttribute('title', 'API 연결됨 · 검사 옵션 준비됨');
      await expect(sidebarStatus.locator('.sidebar-status-copy')).toBeHidden();
      await page.getByRole('button', { name: '사이드바 펼치기' }).click();
    } else {
      const menuButton = page.getByRole('button', { name: '내비게이션 열기' });
      await expect(menuButton).toBeVisible();
      await menuButton.click();
      await expect(sidebarStatus).toBeVisible();
      await page.keyboard.press('Escape');
    }
  }
});

test('sidebar consolidates checking, connected, and offline API states accessibly', async ({ page }) => {
  let finishHealth: (() => void) | undefined;
  await page.route('**/api/v1/health', (route) => new Promise<void>((resolve) => {
    finishHealth = () => { void route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }).then(resolve); };
  }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: readyOptions }));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  const status = page.locator('.sidebar-footnote');
  await expect(status).toContainText('API 확인 중');
  await expect(status).toContainText('검사 옵션 불러오는 중');
  finishHealth?.();
  await expect(page.getByRole('status', { name: 'API 연결됨 · 검사 옵션 준비됨' })).toBeVisible();

  await page.unroute('**/api/v1/health');
  await page.route('**/api/v1/health', (route) => route.abort());
  await page.reload();
  await expect(page.getByRole('status', { name: 'API 연결 안 됨 · 서버 연결 확인 필요' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('로컬 API에 연결할 수 없습니다');
});
