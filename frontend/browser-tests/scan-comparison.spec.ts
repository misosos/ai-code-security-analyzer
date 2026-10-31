import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

function finding(id: string, line: number) {
  return {
    finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`,
    rule_id: `baseline.${id}`,
    severity: 'high',
    verification_status: 'unverified',
    finding_kind: 'pattern',
    file_path: `src/${id}.js`,
    line_number: line,
    evidence_validation_status: 'validated',
    supported_claims: ['match_reported'],
    restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
    validation_error_code: null,
  };
}

function scan(findings: ReturnType<typeof finding>[]) {
  return {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
    finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
    issues: [], limitations: ['scan_result_is_not_safety_proof'], findings,
  };
}

test('baseline comparison can be saved, compared, and read without narrow-screen overflow', async ({ page }) => {
  let scanIndex = 0;
  const responses = [
    scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa', 4), finding('bbbbbbbbbbbbbbbbbbbbbbbb', 7)]),
    scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa', 4), finding('cccccccccccccccccccccccc', 9)]),
  ];
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Local Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: responses[scanIndex++] }));

  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-browser-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('button', { name: '비교 기준으로 지정' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();

  const counts = page.getByLabel('Finding 관찰 차이');
  await expect(counts).toContainText('이번 검사에서만 관찰');
  await expect(counts).toContainText('양쪽에서 관찰');
  await expect(counts).toContainText('기준 검사에서만 관찰');
  await expect(counts).toContainText('1');
  await expect(page.getByText(/취약점의 신규 발생이나 해결을 확정하지 않습니다/)).toBeVisible();
  await expect(page.getByRole('region', { name: '비교 항목 근거' })).toContainText('취약점으로 확정되지 않았습니다');

  const screenshotDir = resolve(process.cwd(), '../output/playwright/phase8a');
  await mkdir(screenshotDir, { recursive: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: resolve(screenshotDir, 'comparison-1440.png'), fullPage: true });

  for (const width of [1920, 1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
      offenders: [...document.querySelectorAll<HTMLElement>('body *')]
        .map((element) => ({ tag: element.tagName, className: element.className.toString(), parent: element.parentElement?.className.toString(), text: element.innerText?.slice(0, 40), left: Math.round(element.getBoundingClientRect().left), right: Math.round(element.getBoundingClientRect().right) }))
        .filter((element) => element.right > document.documentElement.clientWidth + 1)
        .slice(0, 8),
    }));
    expect(dimensions.scroll, `horizontal overflow at ${width}px: ${JSON.stringify(dimensions.offenders)}`).toBeLessThanOrEqual(dimensions.viewport);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: '검사 결과 비교' })).toBeVisible();
  await page.screenshot({ path: resolve(screenshotDir, 'comparison-390.png'), fullPage: true });
  await page.getByRole('button', { name: /기준 검사에서만 관찰/ }).click();
  await expect(page.getByRole('region', { name: '기준 검사에서만 관찰 목록' })).toContainText('src/bbbbbbbbbbbbbbbbbbbbbbbb.js:7');
});
