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

async function installApi(page: import('@playwright/test').Page, scanResponse = response()) {
  let scanCount = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-workspace', label: '합성 분석 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => {
    scanCount += 1;
    return route.fulfill({ json: scanResponse });
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
  expect(boxes[0].y).toBeLessThan(boxes[1].y);
  expect(new Set(boxes.slice(1).map((box) => Math.round(box.y))).size).toBe(1);
  await expect(toolbar.locator('.filter-search-row')).toContainText('검색');
  await expect(toolbar.locator('.filter-select-row')).toContainText('검증 상태');

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
  const analysisDisclosure = page.getByRole('group', { name: '심각도 및 분석가 검토 상세' });
  await expect(core).toContainText('검토 후보');
  await expect(core).toContainText('표시된 결과');
  await expect(core).toContainText('생략된 결과');
  await expect(analysisDisclosure.locator('summary')).toContainText('심각도 분포와 분석가 검토 현황');
  await expect(analysisDisclosure).not.toHaveAttribute('open', '');
  await analysisDisclosure.locator('summary').click();
  const analysis = page.getByRole('group', { name: '검사 분석 요약' });
  await expect(analysis.getByRole('heading', { level: 3, name: '심각도 분포' })).toBeVisible();
  await expect(analysis.getByRole('heading', { name: '분석가 검토 현황' })).toBeVisible();
  await expect(analysis).toContainText('Semgrep 분류');
  await expect(analysis).toContainText('검토 완료');
  await expect(analysis).toContainText('검토 상태는 취약점 확정·수정 완료가 아닙니다.');

  const comparison = page.locator('.scan-comparison');
  await expect(comparison).toContainText('비교 기준 없음');
  await expect(comparison.getByRole('button', { name: /비교 기준/ })).toBeVisible();
  await expect(comparison.getByRole('button', { name: '비교 보고서 내보내기' })).toHaveCount(0);
  await expect(comparison.locator('.comparison-blocked')).toHaveCount(0);
  const compactHeight = await comparison.evaluate((element) => element.getBoundingClientRect().height);
  expect(compactHeight).toBeLessThanOrEqual(72);
  const reviewDisclaimerLines = await page.locator('.analyst-review-scope').first().evaluate((element) => {
    const range = document.createRange();
    range.selectNodeContents(element);
    return range.getClientRects().length;
  });
  expect(reviewDisclaimerLines).toBeGreaterThan(0);

  const sectionOrder = await page.evaluate(() => ['.scan-banner', '.overview-grid.analyst-overview-core', '.findings-section', '.overview-analysis-details', '.scan-comparison']
    .map((selector) => document.querySelector(selector)?.getBoundingClientRect().top ?? -1));
  expect(sectionOrder[0]).toBeLessThan(sectionOrder[1]);
  expect(sectionOrder[1]).toBeLessThan(sectionOrder[2]);
  expect(sectionOrder[2]).toBeLessThan(sectionOrder[3]);
  expect(sectionOrder[3]).toBeLessThan(sectionOrder[4]);

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
  await page.getByRole('button', { name: /비교 기준/ }).click();
  await expect(page.locator('.scan-comparison')).toContainText('비교 기준이 저장되었습니다');
  await expect(page.locator('.scan-comparison')).toContainText('같은 대상과 규칙으로 새 검사를 실행');
  await expect(page.locator('.comparison-baseline-action')).toHaveText('현재 결과로 비교 기준 다시 저장');

  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  const compare = page.locator('.scan-comparison');
  await expect(compare).toContainText('이번 검사에서만 관찰');
  await expect(compare).toContainText('양쪽에서 관찰');
  await expect(compare).toContainText('기준 검사에서만 관찰');
  await expect(compare.getByRole('button', { name: '비교 보고서 내보내기' })).toBeVisible();
  const sections = await page.evaluate(() => ['.findings-section', '.overview-analysis-details', '.scan-comparison', '.result-export-workspace']
    .map((selector) => document.querySelector(selector)?.getBoundingClientRect().top ?? -1));
  expect(sections[0]).toBeLessThan(sections[1]);
  expect(sections[1]).toBeLessThan(sections[2]);
  expect(sections[2]).toBeLessThan(sections[3]);
  expect(scanCount()).toBe(2);
});

test('근거 검증 아이콘은 원형 안에서 중앙 정렬되고 상태별 표시를 유지한다', async ({ page }) => {
  const statusFindings = [
    { ...findings[0], evidence_validation_status: 'validated' },
    { ...findings[1], evidence_validation_status: 'rejected', validation_error_code: 'evidence_unavailable' },
    { ...findings[1], finding_id: 'semgrep:333333333333333333333333', rule_id: 'baseline.synthetic-unavailable', evidence_validation_status: 'unavailable', validation_error_code: 'evidence_unavailable' },
    { ...findings[1], finding_id: 'semgrep:444444444444444444444444', rule_id: `baseline.${'very-long-rule-segment-'.repeat(8)}`, file_path: `src/${'nested-directory-'.repeat(8)}review.js`, evidence_validation_status: 'unavailable', validation_error_code: 'evidence_unavailable' },
  ];
  await installApi(page, response(statusFindings));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);

  const rows = page.getByRole('region', { name: 'Finding 목록' }).getByRole('button');
  await expect(rows).toHaveCount(4);
  await expect(page.locator('.validation-icon.validated')).toHaveCount(1);
  await expect(page.locator('.validation-icon.rejected')).toHaveCount(1);
  await expect(page.locator('.validation-icon.unavailable')).toHaveCount(2);
  const widths = [1920, 1440, 1024, 390, 320];
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 });
    for (const selector of ['.validation-icon.validated', '.validation-icon.rejected', '.validation-icon.unavailable']) {
      const icon = page.locator(selector).first();
      const svg = icon.locator('svg');
      await expect(svg).toHaveAttribute('aria-hidden', 'true');
      const alignment = await icon.evaluate((container) => {
        const iconSvg = container.querySelector('svg');
        if (!iconSvg) throw new Error('검증 아이콘 SVG 누락');
        const outer = container.getBoundingClientRect();
        const inner = iconSvg.getBoundingClientRect();
        return {
          outerWidth: outer.width,
          outerHeight: outer.height,
          innerWidth: inner.width,
          innerHeight: inner.height,
          centerDeltaX: Math.abs(outer.left + outer.width / 2 - inner.left - inner.width / 2),
          centerDeltaY: Math.abs(outer.top + outer.height / 2 - inner.top - inner.height / 2),
        };
      });
      expect(alignment.outerWidth).toBe(20);
      expect(alignment.outerHeight).toBe(20);
      expect(alignment.innerWidth).toBe(12);
      expect(alignment.innerHeight).toBe(12);
      expect(alignment.centerDeltaX).toBeLessThanOrEqual(1);
      expect(alignment.centerDeltaY).toBeLessThanOrEqual(1);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: 'test-results/validation-icon-after.png', fullPage: false });
  await expect(rows.nth(0)).toContainText('근거 연결 구조 확인');
  await expect(rows.nth(1)).toContainText('근거 연결 확인 불가');
  await expect(rows.nth(2)).toContainText('근거 연결 확인 불가');
  await rows.first().focus();
  await expect(rows.first()).toHaveCSS('outline-style', 'solid');
  await rows.first().click();
  await expect(rows.first()).toHaveAttribute('aria-pressed', 'true');
});

test('긴 규칙 ID와 파일 경로는 줄바꿈되며 모든 화면 폭에서 넘치지 않는다', async ({ page }) => {
  const longFinding = {
    ...findings[0],
    finding_id: 'semgrep:333333333333333333333333',
    rule_id: `baseline.${'long-rule-segment-'.repeat(7)}`,
    file_path: `src/${'deeply-nested-directory-'.repeat(5)}review-file.js`,
  };
  await installApi(page, response([longFinding]));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);
  await expect(page.locator('.finding-row')).toContainText('근거 연결 구조 확인');
  await expect(page.locator('.finding-row .unverified-badge')).toContainText('미확인 후보');
  const ruleStyle = await page.locator('.row-rule-id').evaluate((element) => getComputedStyle(element).whiteSpace);
  expect(ruleStyle).toBe('normal');
  const shots = resolve(process.cwd(), '../docs/assets/ui-h8-readability');
  await mkdir(shots, { recursive: true });
  await page.screenshot({ path: resolve(shots, 'long-finding-metadata-1440x900.png') });

  for (const width of [1920, 1536, 1440, 1280, 1024, 768, 600, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll, `긴 Finding 가로 넘침: ${width}px`).toBeLessThanOrEqual(dimensions.client);
  }
});

test('생략 Finding 경고는 접힌 분석 요약과 독립적으로 표시된다', async ({ page }) => {
  await installApi(page, {
    ...response(),
    finding_count: 3,
    displayed_finding_count: 2,
    omitted_finding_count: 1,
    severity_counts: { ...response().severity_counts, high: 2 },
    limitations: [...response().limitations, 'omitted_findings_not_individually_validated'],
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);
  await expect(page.getByRole('alert')).toContainText('1개 Finding이 생략되어');
  await expect(page.locator('.overview-analysis-details')).not.toHaveAttribute('open', '');
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
  const shots = resolve(process.cwd(), '../docs/assets/ui-h8-readability');
  await mkdir(shots, { recursive: true });
  await installApi(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await runScan(page);
  await page.screenshot({ path: resolve(shots, 'results-1440x900-baseline-none.png') });
  await page.locator('.detail-panel').screenshot({ path: resolve(shots, 'finding-detail-1440x900.png') });

  await page.setViewportSize({ width: 1536, height: 960 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, 'results-1536x960.png') });

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, 'results-1280x800.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.locator('#workspace-sidebar').evaluate((element) => element.getBoundingClientRect().right)).toBeLessThan(0);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, 'results-390x844.png') });

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('group', { name: '심각도 및 분석가 검토 상세' }).locator('summary').click();
  await page.screenshot({ path: resolve(shots, 'results-analysis-expanded.png') });
  await page.getByRole('group', { name: '심각도 및 분석가 검토 상세' }).locator('summary').click();
  await page.getByRole('button', { name: /비교 기준/ }).click();
  await page.getByRole('button', { name: '검사 시작' }).click();
  await runScan(page);
  await page.locator('.scan-comparison').scrollIntoViewIfNeeded();
  await page.screenshot({ path: resolve(shots, 'comparison-baseline-set-1440x900.png') });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: resolve(shots, 'results-1440x900-baseline-set.png') });
});
