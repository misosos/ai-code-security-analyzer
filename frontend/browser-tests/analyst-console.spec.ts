import { expect, test, type Page } from '@playwright/test';

const options = {
  targets: [{ id: 'synthetic-project', label: '합성 검수 프로젝트' }],
  rule_profiles: [{ id: 'baseline', label: '기본 검사 규칙', experimental: false }],
};
const finding = (index: number, severity: 'high' | 'medium') => ({
  finding_id: `semgrep:${index.toString(16).padStart(24, '0')}`, rule_id: 'synthetic.review-example', severity,
  verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/module${index}/handler.ts`, line_number: 10 + index,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null,
});
const scan = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 3,
  displayed_finding_count: 3, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 2, medium: 1, low: 0, info: 0 },
  issues: [], limitations: ['scan_result_is_not_safety_proof'],
  findings: [finding(0, 'high'), finding(1, 'high'), finding(2, 'medium')],
};

async function openResults(page: Page) {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: options }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scan }));
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-console-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
}

test('analyst console shows the finding table in the first screen with the detail panel beside it', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  const layout = await page.evaluate(() => {
    const rows = [...document.querySelectorAll('.finding-row')].map((row) => row.getBoundingClientRect());
    const detail = document.querySelector('.results-layout > .detail-panel')!.getBoundingClientRect();
    const note = document.querySelector('#analyst-note')!.getBoundingClientRect();
    return { rowsInFirstScreen: rows.filter((row) => row.bottom <= innerHeight).length, firstRowTop: rows[0].top, detailLeft: detail.left, listRight: rows[0].right, noteBottom: note.bottom, overflow: document.documentElement.scrollWidth - innerWidth };
  });
  expect(layout.rowsInFirstScreen).toBe(3);
  expect(layout.firstRowTop).toBeLessThan(450);
  expect(layout.detailLeft).toBeGreaterThanOrEqual(layout.listRight - 1);
  expect(layout.noteBottom).toBeLessThanOrEqual(900);
  expect(layout.overflow).toBeLessThanOrEqual(0);
});

test('arrow keys move the selected finding and the sidebar summary follows review changes', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  const rows = page.getByLabel('Finding 목록').getByRole('button');
  const summary = page.getByRole('region', { name: '현재 검사 요약' });
  await expect(summary).toContainText('검토 후보 · 확정 아님');
  await expect(summary.locator('.sidebar-legend').first()).toContainText('높음2');
  await expect(summary.locator('.sidebar-legend').last()).toContainText('검토 대기3');

  await rows.first().focus();
  await page.keyboard.press('ArrowDown');
  await expect(rows.nth(1)).toBeFocused();
  await expect(rows.nth(1)).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('src/module1/handler.ts:11');
  await page.keyboard.press('End');
  await expect(rows.nth(2)).toHaveAttribute('aria-pressed', 'true');
  await page.keyboard.press('Home');
  await expect(rows.first()).toHaveAttribute('aria-pressed', 'true');

  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await expect(rows.first()).toContainText('분석가: 검토 완료');
  await expect(summary.locator('.sidebar-legend').last()).toContainText('검토 완료1');
  await expect(summary.locator('.sidebar-legend').last()).toContainText('검토 대기2');
});

test('on a narrow screen selecting a finding moves focus to the detail area and back', async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await openResults(page);
  const rows = page.getByLabel('Finding 목록').getByRole('button');
  await rows.nth(1).click();
  await expect(page.getByLabel('선택한 Finding 상세')).toBeFocused();
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('src/module1/handler.ts:11');
  await page.getByRole('button', { name: '목록으로 돌아가기' }).click();
  await expect(rows.nth(1)).toBeFocused();
  for (const width of [768, 390, 320]) {
    await page.setViewportSize({ width, height: 800 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth), `${width}px overflow`).toBeLessThanOrEqual(0);
  }
});
