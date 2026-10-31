import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const options = {
  targets: [{ id: 'synthetic-project', label: '합성 검수 프로젝트' }],
  rule_profiles: [{ id: 'baseline', label: '기본 검사 규칙', experimental: false }],
};
const scan = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1,
  displayed_finding_count: 1, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  issues: [], limitations: ['scan_result_is_not_safety_proof'],
  findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.review-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/review.ts', line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
};
const screenshots = resolve(process.cwd(), '../docs/assets/ui-d5a');

test('D5A desktop shell removes full-width header and moves brand into top-aligned sidebar', async ({ page }) => {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: options }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scan }));
  await mkdir(screenshots, { recursive: true });

  for (const viewport of [
    { width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1280, height: 800 },
    { width: 1000, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }, { width: 320, height: 800 },
  ]) {
    await page.setViewportSize(viewport);
    await page.goto('/');
    await expect(page.getByRole('status', { name: 'API 연결됨 · 검사 옵션 준비됨' })).toBeVisible();
    await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
    const metrics = await page.evaluate(() => {
      const rect = (selector: string) => {
        const element = document.querySelector(selector);
        if (!element) throw new Error(`missing ${selector}`);
        const box = element.getBoundingClientRect();
        return { x: Math.round(box.x), y: Math.round(box.y), width: Math.round(box.width), height: Math.round(box.height) };
      };
      return {
        header: rect('.mobile-topbar'), sidebar: rect('.workspace-sidebar'), main: rect('.dashboard-main'),
        titleSize: getComputedStyle(document.querySelector('.workspace-title h1')!).fontSize,
        navSize: getComputedStyle(document.querySelector('.nav-item')!).fontSize,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        sidebarTop: document.querySelector('.workspace-sidebar')!.getBoundingClientRect().top,
      };
    });
    console.log('[UI-D5A shell]', JSON.stringify({ viewport, ...metrics }));
    expect(metrics.overflow, `${viewport.width}px horizontal overflow`).toBeLessThanOrEqual(0);
    if (viewport.width > 760) {
      await expect(page.locator('.mobile-topbar')).toBeHidden();
      expect(metrics.header.height).toBe(0);
      expect(metrics.sidebarTop).toBe(0);
      expect(metrics.sidebar.height).toBe(viewport.height);
      expect(metrics.main.x).toBe(metrics.sidebar.width);
      await expect(page.locator('.sidebar-brand')).toBeVisible();
      await expect(page.getByRole('link', { name: 'AI Code Security Analyzer' })).toBeVisible();
      expect(Number.parseFloat(metrics.navSize)).toBeGreaterThanOrEqual(18);
    } else {
      await expect(page.locator('.mobile-topbar')).toBeVisible();
      await expect(page.getByRole('button', { name: '내비게이션 열기' })).toBeVisible();
      if (viewport.width === 390) await page.screenshot({ path: resolve(screenshots, 'mobile-start-390x844.png'), fullPage: true, animations: 'disabled' });
      await page.getByRole('button', { name: '내비게이션 열기' }).click();
      await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
      if (viewport.width === 390) await page.screenshot({ path: resolve(screenshots, 'mobile-menu-390x844.png'), fullPage: true, animations: 'disabled' });
      await page.keyboard.press('Escape');
      await expect(page.getByRole('button', { name: '내비게이션 열기' })).toBeFocused();
      await page.getByRole('button', { name: '내비게이션 열기' }).click();
      await page.getByRole('button', { name: '사용 안내' }).click();
      await expect(page.getByRole('heading', { name: '검사 방법' })).toBeVisible();
      await expect(page.getByRole('button', { name: '내비게이션 열기' })).toBeFocused();
    }
    if (viewport.width === 1440) await page.screenshot({ path: resolve(screenshots, 'start-1440x900.png'), fullPage: true, animations: 'disabled' });
    if (viewport.width === 1920) await page.screenshot({ path: resolve(screenshots, 'start-1920x1080.png'), fullPage: true, animations: 'disabled' });
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await page.getByRole('button', { name: '검사 결과' }).click();
  await expect(page.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeVisible();
  await page.screenshot({ path: resolve(screenshots, 'empty-results-1440x900.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 시작' }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-d5a-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('Finding 목록')).toContainText('src/review.ts:12');
  await page.screenshot({ path: resolve(screenshots, 'finding-results-1440x900.png'), fullPage: true, animations: 'disabled' });
  await expect(page.getByRole('link', { name: 'AI Code Security Analyzer' })).toHaveAttribute('href', '#main-content');
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '사용 안내' }).click();
  await expect(page.getByRole('heading', { name: '검사 방법' })).toBeVisible();
  await page.screenshot({ path: resolve(screenshots, 'guide-1440x900.png'), fullPage: true, animations: 'disabled' });
});
