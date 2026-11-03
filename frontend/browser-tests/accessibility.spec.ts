import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const evidenceDir = resolve(process.cwd(), '../docs/assets/phase8g');

const finding = {
  finding_id: 'semgrep:0123456789abcdef01234567',
  rule_id: 'baseline.javascript-dynamic-eval',
  severity: 'high',
  verification_status: 'unverified',
  finding_kind: 'pattern',
  file_path: 'src/synthetic-review.js',
  line_number: 12,
  evidence_validation_status: 'validated',
  supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null,
};

function scan(overrides: Record<string, unknown> = {}) {
  return {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
    finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    issues: [], limitations: ['scan_result_is_not_safety_proof'], findings: [finding], ...overrides,
  };
}

async function fixture(page: Page, response: Record<string, unknown> = scan()) {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: 'Synthetic Review Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: response }));
}

async function runScan(page: Page) {
  await page.getByLabel('로컬 API 토큰').fill('synthetic-a11y-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.locator('#scan-result-title')).toBeVisible();
}

async function tabTo(page: Page, locator: ReturnType<Page['getByRole']> | ReturnType<Page['getByLabel']> | ReturnType<Page['getByText']>, limit = 80) {
  const seen: string[] = [];
  for (let index = 0; index < limit; index += 1) {
    if (await locator.evaluate((element) => document.activeElement === element).catch(() => false)) return;
    await page.keyboard.press('Tab');
    seen.push(await page.evaluate(() => { const element = document.activeElement as HTMLElement | null; return element ? `${element.tagName.toLowerCase()}#${element.id}.${element.className} aria=${element.getAttribute('aria-label') ?? ''}` : 'none'; }));
  }
  throw new Error(`keyboard_target_not_reachable: ${seen.slice(-12).join(' | ')}`);
}

async function expectAxeClean(page: Page, state: string) {
  const result = await new AxeBuilder({ page }).analyze();
  const violations = result.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    description: violation.description,
    nodes: violation.nodes.map((node) => ({ target: node.target, html: node.html, summary: node.failureSummary, any: node.any, all: node.all, none: node.none })),
  }));
  if (violations.length) console.error(`[axe ${state}] ${JSON.stringify(violations)}`);
  expect(violations, `axe violations in ${state}`).toEqual([]);
}

test('axe: 검사 시작 폼의 입력 이름, 버튼, 상태와 색상 대비', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  await expect(page.getByLabel('검사 대상')).toBeVisible();
  await expect(page.getByLabel('검사 규칙 모음')).toBeVisible();
  await expect(page.getByLabel('로컬 API 토큰')).toBeVisible();
  await expectAxeClean(page, '검사 시작');
});

test('axe: Finding 결과, 분석가 검토, 내보내기와 JSON 복원 미리보기', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  await page.setViewportSize({ width: 1440, height: 900 });
  await runScan(page);
  const nav = page.getByRole('navigation', { name: '화면 이동' });
  await nav.getByRole('button', { name: '검사 결과' }).click();
  await page.getByLabel('Finding 목록').getByRole('button').click();
  await expectAxeClean(page, 'Finding 상세 및 검토 상태');
  await page.getByText('판단 근거, 단계별 검토 절차 및 권장 조치').click();
  await expectAxeClean(page, '분석가 검토 가이드 펼침');

  await page.getByLabel('수동 검토 상태').selectOption('needs_followup');
  await page.getByLabel('분석가 메모').fill('합성 접근성 검사 메모');
  await mkdir(evidenceDir, { recursive: true });
  await page.screenshot({ path: resolve(evidenceDir, 'finding-review-1440.png'), fullPage: true });
  await page.getByText('분석가 검토 기록 내보내기', { exact: true }).click();
  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  await expectAxeClean(page, '보고서 및 백업 컨트롤');

  const backup = {
    schema_version: 'analyst-review-backup/v1',
    scan_context: { target_id: 'synthetic-project', rule_profile_id: 'baseline', experimental: false, semgrep_version: '1.182.1', scan_status: 'completed', received_at: '2026-11-01T00:00:00.000Z', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0 },
    findings: [{ finding_id: finding.finding_id, rule_id: finding.rule_id, file_path: finding.file_path, line_number: finding.line_number, severity: finding.severity, finding_kind: finding.finding_kind, review_status: 'reviewed' }],
  };
  await page.getByLabel('검토 기록 불러오기(JSON)').setInputFiles({ name: 'synthetic-backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backup)) });
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toBeVisible();
  await expectAxeClean(page, '복원 미리보기');
  await page.screenshot({ path: resolve(evidenceDir, 'backup-preview-1440.png'), fullPage: true });
  await page.getByText('Finding별 기록 확인 (1)', { exact: true }).click();
  await expectAxeClean(page, 'Finding별 복원 적용 및 취소');
});

test('axe: 비교 기준, 비교 범주와 비교 보고서 내보내기', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  await runScan(page);
  await page.getByRole('button', { name: /비교 기준/ }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 시작' }).click();
  await runScan(page);
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' }).click();
  await page.getByText('검사 결과 비교', { exact: true }).click();
  await expectAxeClean(page, '검사 결과 비교');
  await page.getByRole('button', { name: /양쪽에서 관찰/ }).click();
  await page.getByRole('region', { name: '비교 항목 후속 검토' }).getByText('권장 후속 검토 절차').click();
  await expectAxeClean(page, '비교 결과 후속 검토');
});

test('axe: 사용 안내의 제목 계층과 접이식 도움말', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '사용 안내' }).click();
  await page.getByText('서버 관리자 설정', { exact: true }).click();
  await page.getByText('보안 용어 설명', { exact: true }).click();
  await expectAxeClean(page, '사용 안내');
});

test('axe: API 오류 및 연결 복구 안내', async ({ page }) => {
  await page.route('**/api/v1/health', (route) => route.abort());
  await page.route('**/api/v1/options', (route) => route.abort());
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('로컬 API에 연결할 수 없습니다');
  await expectAxeClean(page, 'API 연결 오류');
});

test('axe: 부분 검사 및 Finding 0건 상태', async ({ page }) => {
  const partial = scan({ scan_status: 'partial', completed: false });
  await fixture(page, partial);
  await page.goto('/');
  await runScan(page);
  await expectAxeClean(page, '부분 검사');

  await page.reload();
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scan({ finding_count: 0, displayed_finding_count: 0, omitted_finding_count: 0, severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [] }) }));
  await runScan(page);
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' }).click();
  await expect(page.getByRole('heading', { name: '발견 항목이 없습니다' })).toBeVisible();
  await expectAxeClean(page, 'Finding 0건');
});

test('axe: 잘못된 JSON 백업과 메모 길이 오류', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  await runScan(page);
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' }).click();
  await page.getByLabel('선택한 Finding 상세').getByLabel('분석가 메모').fill('x'.repeat(2049));
  await expect(page.getByRole('alert')).toContainText(/2 KiB/);
  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  await page.getByLabel('검토 기록 불러오기(JSON)').setInputFiles({ name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{broken') });
  await expect(page.getByText(/JSON 문법을 확인할 수 없습니다/)).toBeVisible();
  await expectAxeClean(page, '잘못된 백업 및 메모 입력 오류');
});

test('키보드만으로 모바일 Drawer를 열고 닫으며 포커스를 복귀한다', async ({ page }) => {
  await fixture(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const toggle = page.getByRole('button', { name: '내비게이션 열기' });
  await toggle.focus();
  await page.keyboard.press('Enter');
  const drawer = page.getByRole('dialog', { name: '주 메뉴' });
  await expect(drawer).toBeVisible();
  await expect(page.getByRole('button', { name: '검사 시작' })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(drawer).toHaveCount(0);
  await expect(toggle).toBeFocused();
  await page.keyboard.press('Space');
  await expect(drawer).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: '검사 결과' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(drawer).toHaveCount(0);
  await expect(page.getByRole('heading', { name: '검사 결과', exact: true })).toBeVisible();
});

test('키보드 탐색으로 검사·Finding 검토·검색·보고서·백업·수동 복원 흐름을 수행한다', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  const target = page.getByLabel('검사 대상');
  await tabTo(page, target);
  await page.keyboard.press('ArrowDown');
  const rules = page.getByLabel('검사 규칙 모음');
  await tabTo(page, rules);
  await page.keyboard.press('ArrowDown');
  const token = page.getByLabel('로컬 API 토큰');
  await tabTo(page, token);
  await page.keyboard.type('keyboard-synthetic-token');
  const launch = page.getByRole('button', { name: '검사 실행' });
  await tabTo(page, launch);
  await page.keyboard.press('Enter');
  await expect(page.locator('#scan-result-title')).toBeVisible();

  const resultNavigation = page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' });
  await tabTo(page, resultNavigation);
  await page.keyboard.press('Enter');
  const search = page.getByRole('searchbox', { name: '검색' });
  await tabTo(page, search);
  await page.keyboard.type('dynamic-eval');
  await page.keyboard.press('Control+A');
  await page.keyboard.press('Backspace');
  const findingRow = page.getByLabel('Finding 목록').getByRole('button').first();
  await tabTo(page, findingRow);
  await page.keyboard.press('Enter');
  const reviewStatus = page.getByLabel('수동 검토 상태');
  await tabTo(page, reviewStatus);
  await expect(reviewStatus).toBeFocused();
  // Playwright's headless and headed Chromium do not commit the platform-native select popup
  // from page.keyboard events on macOS. Keyboard focus is verified here; choosing an option is
  // covered by the native control API and is left for the real Safari checklist.
  await reviewStatus.selectOption('needs_followup');
  await expect(reviewStatus).toHaveValue('needs_followup');
  const note = page.getByLabel('분석가 메모');
  await tabTo(page, note);
  await page.keyboard.type('keyboard-only synthetic note');

  await expect(findingRow).toBeVisible();

  const reportSummary = page.getByText('분석가 검토 기록 내보내기', { exact: true });
  await tabTo(page, reportSummary);
  await page.keyboard.press('Enter');
  const markdownButton = page.getByRole('button', { name: /Markdown 다운로드/ });
  await tabTo(page, markdownButton);
  const markdownPromise = page.waitForEvent('download');
  await page.keyboard.press('Enter');
  const markdown = await markdownPromise;
  expect(markdown.suggestedFilename()).toBe('ai-code-security-analyst-review.md');

  const backupSummary = page.getByText('검토 기록 백업 및 복원', { exact: true });
  await tabTo(page, backupSummary);
  await page.keyboard.press('Enter');
  const backupButton = page.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' });
  await tabTo(page, backupButton);
  const backupPromise = page.waitForEvent('download');
  await page.keyboard.press('Enter');
  const backupDownload = await backupPromise;
  expect(backupDownload.suggestedFilename()).toBe('ai-code-security-analyst-review-backup.json');

  const backupInput = page.getByLabel('검토 기록 불러오기(JSON)');
  await tabTo(page, backupInput);
  await backupInput.setInputFiles(await backupDownload.path() ?? '');
  const previewSummary = page.getByText('Finding별 기록 확인 (1)', { exact: true });
  await expect(previewSummary).toBeVisible();
  await tabTo(page, previewSummary);
  await page.keyboard.press('Space');
  const apply = page.getByLabel('검토 기록 복원 미리보기').getByRole('button', { name: '이 기록 적용' });
  await tabTo(page, apply);
  await page.keyboard.press('Enter');
  await expect(reviewStatus).toHaveValue('needs_followup');

  const clear = page.getByRole('button', { name: '결과 지우기' });
  await tabTo(page, clear);
  const clearConfirm = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  await page.keyboard.press('Enter');
  await clearConfirm;
  await expect(page.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeVisible();
});

test('200% CSS viewport 대리 검증: 필수 UI가 좁은 폭에서 겹치거나 가로 넘치지 않는다', async ({ page }) => {
  await fixture(page);
  await page.goto('/');
  await runScan(page);
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' }).click();
  for (const width of [720, 512, 400, 320]) {
    await page.setViewportSize({ width, height: 800 });
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll, `horizontal overflow at CSS viewport ${width}`).toBeLessThanOrEqual(dimensions.client);
    await expect(page.getByRole('heading', { name: '검사 결과', exact: true })).toBeVisible();
    await expect(page.getByLabel('Finding 목록')).toBeVisible();
    await expect(page.getByLabel('수동 검토 상태')).toBeVisible();
    if (width === 320) {
      await mkdir(evidenceDir, { recursive: true });
      await page.screenshot({ path: resolve(evidenceDir, 'css-viewport-reflow-320.png'), fullPage: true });
    }
  }
});

test('1280px 데스크톱의 검토 요약이 좁은 열에 눌리지 않는다', async ({ page }) => {
  await fixture(page);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/');
  await runScan(page);
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 결과' }).click();
  const layout = await page.locator('.overview-analysis-grid').evaluate((element) => {
    const summary = element.querySelector('.analyst-review-summary') as HTMLElement;
    const heading = summary.querySelector('.analyst-review-summary-heading') as HTMLElement;
    const title = heading.querySelector('h2') as HTMLElement;
    const scope = heading.querySelector('span') as HTMLElement;
    const titleBox = title.getBoundingClientRect();
    const scopeBox = scope.getBoundingClientRect();
    return {
      columns: getComputedStyle(element).gridTemplateColumns.split(' ').length,
      summaryColumn: getComputedStyle(summary).gridColumn,
      summaryWidth: summary.getBoundingClientRect().width,
      titleRight: titleBox.right,
      scopeLeft: scopeBox.left,
      scopeRight: scopeBox.right,
      overviewRight: element.getBoundingClientRect().right,
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: document.documentElement.clientWidth,
    };
  });
  expect(layout.columns).toBe(2);
  expect(layout.summaryWidth).toBeGreaterThan(300);
  expect(layout.summaryColumn).not.toBe('1 / -1');
  expect(layout.scopeLeft).toBeGreaterThanOrEqual(layout.titleRight - 1);
  expect(layout.scopeRight).toBeLessThanOrEqual(layout.overviewRight + 1);
  expect(layout.documentWidth).toBe(layout.viewportWidth);
});
