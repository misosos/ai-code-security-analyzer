import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { expect, test } from '@playwright/test';
import { measureAnalystLayout } from './analyst-layout-measurements';

const findings = [
  {
    finding_id: 'semgrep:111111111111111111111111', rule_id: 'baseline.synthetic-first', severity: 'high',
    verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/stable.js', line_number: 8,
    evidence_validation_status: 'validated', supported_claims: ['match_reported'],
    restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
    validation_error_code: null,
  },
  {
    finding_id: 'semgrep:222222222222222222222222', rule_id: 'baseline.synthetic-second', severity: 'medium',
    verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/review.js', line_number: 19,
    evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null,
  },
];

function response(currentFindings = findings) {
  return {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
    finding_count: currentFindings.length, displayed_finding_count: currentFindings.length, omitted_finding_count: 0,
    severity_counts: {
      critical: 0,
      high: currentFindings.filter((finding) => finding.severity === 'high').length,
      medium: currentFindings.filter((finding) => finding.severity === 'medium').length,
      low: 0,
      info: 0,
    },
    issues: [], findings: currentFindings, limitations: ['scan_result_is_not_safety_proof'],
  };
}

async function installApi(page: import('@playwright/test').Page) {
  let scanCount = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-workspace', label: '합성 분석 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => {
    scanCount += 1;
    return route.fulfill({ json: response() });
  });
  return () => scanCount;
}

async function runScan(page: import('@playwright/test').Page) {
  await page.getByLabel('로컬 API 토큰').fill('synthetic-workspace-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
}

test('Finding 검색과 필터는 제목에서 분리된 동일 Toolbar에서 동작한다', async ({ page }) => {
  await installApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);

  const title = page.getByRole('heading', { name: /발견 항목/ });
  const toolbar = page.getByRole('group', { name: 'Finding 검색 및 필터' });
  await expect(title).toBeVisible();
  await expect(page.locator('.results-title select')).toHaveCount(0);
  await expect(toolbar.getByRole('searchbox', { name: '검색' })).toBeVisible();
  for (const label of ['분석가 검토', '심각도', '탐지 유형', '검증 상태']) {
    await expect(toolbar.getByRole('combobox', { name: label })).toBeVisible();
  }

  const controls = toolbar.locator('input, select');
  const boxes = await controls.evaluateAll((elements) => elements.map((element) => {
    const rect = element.getBoundingClientRect();
    return { x: rect.x, y: rect.y, height: rect.height };
  }));
  expect(boxes).toHaveLength(5);
  expect(new Set(boxes.map((box) => Math.round(box.height))).size).toBe(1);
  expect(Math.max(...boxes.map((box) => box.y)) - Math.min(...boxes.map((box) => box.y))).toBeLessThanOrEqual(2);

  await toolbar.getByRole('searchbox', { name: '검색' }).fill('stable.js');
  await expect(page.getByRole('region', { name: 'Finding 목록' }).getByRole('button')).toHaveCount(1);
  await toolbar.getByRole('combobox', { name: '심각도' }).selectOption('medium');
  await expect(page.getByRole('region', { name: 'Finding 목록' })).toContainText('검색 또는 필터와 일치하는 결과가 없습니다');
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
});

test('검사 요약은 핵심 수치와 분석 정보를 분리하고 기준 없는 비교는 compact 상태다', async ({ page }) => {
  await installApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);

  const core = page.getByRole('region', { name: '핵심 검사 수치' });
  const analysis = page.getByRole('group', { name: '검사 분석 요약' });
  await expect(core).toContainText('검토 후보');
  await expect(core).toContainText('표시된 결과');
  await expect(core).toContainText('생략된 결과');
  await expect(analysis.getByRole('heading', { level: 3, name: '심각도 분포' })).toBeVisible();
  await expect(analysis.getByRole('heading', { name: '분석가 검토 현황' })).toBeVisible();
  await expect(analysis).toContainText('Semgrep 분류');
  await expect(analysis).toContainText('검토 완료');
  await expect(analysis).toContainText('검토 상태는 취약점 확정·수정 완료가 아닙니다.');

  const comparison = page.locator('.scan-comparison');
  await expect(comparison).toContainText('비교 기준 없음');
  await expect(comparison.getByRole('button', { name: '비교 기준으로 지정' })).toBeVisible();
  await expect(comparison.getByRole('button', { name: '비교 보고서 내보내기' })).toHaveCount(0);
  await expect(comparison.locator('.comparison-blocked')).toHaveCount(0);
  const compactHeight = await comparison.evaluate((element) => element.getBoundingClientRect().height);
  expect(compactHeight).toBeLessThanOrEqual(72);
  const reviewDisclaimerLines = await page.locator('.analyst-review-scope').first().evaluate((element) => {
    const range = document.createRange();
    range.selectNodeContents(element);
    return range.getClientRects().length;
  });
  expect(reviewDisclaimerLines).toBe(1);

  const positions = await page.evaluate(() => {
    const list = document.querySelector('.results-layout');
    const first = document.querySelector('.finding-row');
    if (!list || !first) throw new Error('Finding 목록 측정 대상 누락');
    return {
      listY: Math.round(list.getBoundingClientRect().top + window.scrollY),
      firstY: Math.round(first.getBoundingClientRect().top + window.scrollY),
    };
  });
  console.log('[analyst workspace vertical layout]', JSON.stringify(await measureAnalystLayout(page)));
  console.log('[analyst workspace Finding coordinates]', JSON.stringify(positions));
  expect(positions.listY).toBeLessThan(810);
  expect(positions.firstY).toBeLessThan(870);
  expect(positions.listY, '목록 위치는 Linux 글꼴 메트릭 변동에도 20px 이상 여유를 둔다').toBeLessThan(790);
  expect(positions.firstY, '첫 Finding 행은 Linux 글꼴 메트릭 변동에도 20px 이상 여유를 둔다').toBeLessThan(850);
});

test('기준 저장 후 비교 범주와 기존 검토 기능이 유지된다', async ({ page }) => {
  const scanCount = await installApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);
  await page.getByRole('button', { name: '비교 기준으로 지정' }).click();
  await expect(page.locator('.comparison-heading')).toContainText('비교 기준 교체');

  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  const compare = page.locator('.scan-comparison');
  await expect(compare).toContainText('이번 검사에서만 관찰');
  await expect(compare).toContainText('양쪽에서 관찰');
  await expect(compare).toContainText('기준 검사에서만 관찰');
  await expect(compare.getByRole('button', { name: '비교 보고서 내보내기' })).toBeVisible();
  expect(scanCount()).toBe(2);
});

test('검색 및 필터 Toolbar는 지정한 모든 폭에서 가로 넘침이 없다', async ({ page }) => {
  await installApi(page);
  await page.goto('/');
  await runScan(page);
  for (const width of [1920, 1440, 1280, 1024, 768, 600, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
      toolbar: document.querySelector('.filter-row')?.getBoundingClientRect().width ?? 0,
    }));
    expect(dimensions.scroll, `가로 넘침: ${width}px`).toBeLessThanOrEqual(dimensions.client);
    expect(dimensions.toolbar).toBeGreaterThan(0);
  }
});


test('합성 Finding 화면 스크린샷을 필수 폭과 비교 상태별로 저장한다', async ({ page }) => {
  const shots = resolve(process.cwd(), '../docs/assets/ui-h8-ui');
  await mkdir(shots, { recursive: true });
  await installApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);
  await page.screenshot({ path: resolve(shots, 'results-1440x900-baseline-none.png') });
  await page.locator('.detail-panel').screenshot({ path: resolve(shots, 'finding-detail-1440x900.png') });

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, 'results-1280x800.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.locator('#workspace-sidebar').evaluate((element) => element.getBoundingClientRect().right)).toBeLessThan(0);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, 'results-390x844.png') });

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: '비교 기준으로 지정' }).click();
  await page.getByRole('button', { name: '검사 시작' }).click();
  await runScan(page);
  await page.screenshot({ path: resolve(shots, 'results-1440x900-baseline-set.png') });
});
