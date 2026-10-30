import { expect, test } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

test('browser loads dashboard, accepts token in memory, and displays validated evidence safely', async ({ page }) => {
  const token = 'browser-smoke-token-that-is-not-persisted';
  const filePath = 'src/<img src=x onerror=alert(1)>.js';
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Local Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }, { id: 'command-injection-experimental', label: 'Experimental Command Injection', experimental: true }],
  } }));
  await page.route('**/api/v1/scans', async (route) => {
    expect(route.request().headers()['x-local-api-token']).toBe(token);
    expect(route.request().url()).not.toContain(token);
    expect(route.request().postData() ?? '').not.toContain(token);
    await route.fulfill({ json: {
      scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
      findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'experimental.command-injection', severity: 'high', verification_status: 'unverified', finding_kind: 'taint', file_path: filePath, line_number: 7, evidence_validation_status: 'validated', supported_claims: ['match_reported','taint_rule_match_reported'], restricted_claims: [{ claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent'] }, { claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
    } });
  });

  await page.goto('/');
  await expect(page.getByText(/연결됨/)).toBeVisible();
  await expect(page.getByRole('option', { name: 'Experimental · Experimental Command Injection' })).toBeAttached();
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByText('기술 근거와 제한 자세히 보기').click();
  await expect(page.getByText('신뢰된 taint 규칙 매치 보고')).toBeVisible();
  await expect(page.getByText(/trace가 제공되지 않았습니다/)).toBeVisible();
  await expect(page.getByRole('img')).toHaveCount(0);
  await expect(page.getByLabel('선택한 Finding 상세').getByText(`${filePath}:7`, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('mobile layout fits 320px and token controls are keyboard reachable', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 780 });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'local-project', label: 'Local Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.goto('/');
  await expect(page.getByLabel('로컬 API 토큰')).toBeVisible();
  const dimensions = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
  await page.getByLabel('검사 대상').focus();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('검사 규칙 모음')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('로컬 API 토큰')).toBeFocused();
  await page.getByLabel('로컬 API 토큰').fill('keyboard-smoke-token');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: '화면의 API 토큰 지우기' })).toBeFocused();
});

test('browser preserves scan context, downloads the current summary on click, and clears only in-memory results', async ({ page }) => {
  const token = 'browser-export-token-not-for-report';
  let scans = 0;
  const externalRequests: string[] = [];
  page.on('request', (request) => { if (!request.url().startsWith('http://127.0.0.1:4173')) externalRequests.push(request.url()); });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'local-project', label: 'Local Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }, { id: 'command-injection-experimental', label: 'Experimental Command Injection', experimental: true }],
  } }));
  await page.route('**/api/v1/scans', async (route) => {
    scans += 1;
    expect(route.request().headers()['x-local-api-token']).toBe(token);
    await route.fulfill({ json: {
      scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
      severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
      findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'baseline.test-rule', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/check.js', line_number: 4, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
    } });
  });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('이 결과를 생성한 검사 설정')).toContainText('Baseline Rules');
  await page.getByRole('button', { name: '검사 시작', exact: true }).click();
  await page.getByLabel('검사 규칙 모음').selectOption('command-injection-experimental');
  await expect(page.getByRole('alert')).toContainText('이전 검사 설정(Local Project · Baseline Rules)');
  await page.getByRole('button', { name: /검사 결과/ }).click();

  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '현재 검사 결과 내보내기' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('ai-code-security-ui-review-summary.md');
  const stream = await download.createReadStream();
  let markdown = '';
  for await (const chunk of stream!) markdown += chunk.toString('utf8');
  expect(markdown).toContain('Baseline Rules');
  expect(markdown).toContain('Semgrep 규칙 매치 보고');
  expect(markdown).toContain('취약점 확정 문서가 아니며');
  expect(markdown).not.toContain('Experimental Command Injection (command-injection-experimental)');
  expect(markdown).not.toContain(token);
  expect(scans).toBe(1);
  expect(externalRequests).toEqual([]);

  await page.getByRole('button', { name: '결과 지우기' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toHaveCount(0);
  await page.getByRole('button', { name: '검사 시작', exact: true }).click();
  await expect(page.getByLabel('로컬 API 토큰')).toHaveValue(token);
  await page.reload();
  await expect(page.getByLabel('로컬 API 토큰')).toHaveValue('');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
});

test('cyberpunk workspace stays usable without horizontal overflow across desktop, tablet, and mobile viewports', async ({ page }) => {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-app', label: 'Synthetic Review Project' }],
    rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 2, displayed_finding_count: 2, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
    findings: [
      { finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/routes/<fixture>.js', line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
      { finding_id: 'semgrep:1123456789abcdef01234567', rule_id: 'synthetic.html-example', severity: 'medium', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/ui/Notice.tsx', line_number: 28, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
    ],
  } }));
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-viewport-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();

  const viewportMetrics: Array<Record<string, unknown>> = [];
  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const dimensions = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
    expect(dimensions.content, `horizontal overflow at ${viewport.width}px`).toBeLessThanOrEqual(dimensions.viewport);
    await expect(page.getByRole('heading', { name: '발견 항목' })).toBeVisible();
    await expect(page.getByLabel('Finding 목록')).toBeVisible();
    await expect(page.getByLabel('선택한 Finding 상세')).toBeVisible();
    const presentation = await page.evaluate(() => {
      const firstRow = document.querySelector('.finding-row');
      const detail = document.querySelector('.detail-panel');
      const title = firstRow?.querySelector('.row-main > strong');
      const filterLabel = document.querySelector('.filter-row label:not(.search-field)');
      const rowLocation = firstRow?.querySelector('.row-location');
      const detailCopy = document.querySelector('.detail-location small');
      const rect = (element: Element | null) => { const box = element?.getBoundingClientRect(); return box ? { x: Math.round(box.x), y: Math.round(box.y), width: Math.round(box.width), height: Math.round(box.height) } : null; };
      return {
        sidebar: rect(document.querySelector('.workspace-sidebar')),
        main: rect(document.querySelector('.dashboard-main')),
        listPanel: rect(document.querySelector('.finding-list')),
        detailPanel: rect(detail),
        firstRowTop: firstRow?.getBoundingClientRect().top ?? Number.POSITIVE_INFINITY,
        detailTop: detail?.getBoundingClientRect().top ?? Number.POSITIVE_INFINITY,
        rowTitleSize: Number.parseFloat(title ? getComputedStyle(title).fontSize : '0'),
        filterLabelSize: Number.parseFloat(filterLabel ? getComputedStyle(filterLabel).fontSize : '0'),
        rowLocationSize: Number.parseFloat(rowLocation ? getComputedStyle(rowLocation).fontSize : '0'),
        detailCopySize: Number.parseFloat(detailCopy ? getComputedStyle(detailCopy).fontSize : '0'),
      };
    });
    console.log('[Readability result metrics]', JSON.stringify({ viewport, presentation }));
    const undersizedResultText = await page.evaluate(() => {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const tooSmall: Array<{ text: string; fontSize: string; selector: string }> = [];
      while (walker.nextNode()) {
        const node = walker.currentNode;
        const text = node.textContent?.trim() ?? '';
        const parent = node.parentElement;
        if (!text || !parent || parent.closest('.sr-only,[aria-hidden="true"]') || parent.tagName === 'OPTION') continue;
        const style = getComputedStyle(parent);
        if (style.display === 'none' || style.visibility === 'hidden' || parent.getClientRects().length === 0) continue;
        if (Number.parseFloat(style.fontSize) < 14) tooSmall.push({ text: text.slice(0, 60), fontSize: style.fontSize, selector: `${parent.tagName.toLowerCase()}.${parent.className}` });
      }
      return tooSmall;
    });
    expect(undersizedResultText).toEqual([]);
    viewportMetrics.push({ viewport, ...presentation, overflow: dimensions.content - dimensions.viewport });
    expect(presentation.rowTitleSize).toBeGreaterThanOrEqual(16);
    expect(presentation.filterLabelSize).toBeGreaterThanOrEqual(14);
    expect(presentation.rowLocationSize).toBeGreaterThanOrEqual(15);
    expect(presentation.detailCopySize).toBeGreaterThanOrEqual(15);
    if (viewport.width >= 1440) {
      expect(presentation.firstRowTop).toBeLessThan(viewport.height);
      expect(presentation.detailTop).toBeLessThan(viewport.height);
    } else if (viewport.width === 1280) {
      expect(presentation.detailTop).toBeLessThan(viewport.height + 140);
      expect(presentation.firstRowTop).toBeLessThan(viewport.height + 220);
    }
  }
  await writeFile(resolve(process.cwd(), '../docs/assets/ui-large-type-readability-36-9b-z/readability-audit/responsive-result-metrics.json'), JSON.stringify(viewportMetrics, null, 2));

  await page.getByLabel('파일 경로, 규칙 이름 또는 ID 검색').fill('synthetic.html-example');
  await expect(page.getByLabel('Finding 목록').getByRole('button')).toHaveCount(1);
  await expect(page.getByText('src/routes/<fixture>.js:12')).toHaveCount(0);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('large-type scale remains readable across workspace pages and target viewports', async ({ page }) => {
  const output = resolve(process.cwd(), '../docs/assets/ui-large-type-readability-36-9b-z/readability-audit');
  await mkdir(output, { recursive: true });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-app', label: '합성 검토 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: '기본 보안 규칙', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
    findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/example.ts', line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
  } }));
  await page.goto('/');

  const samples: Array<Record<string, unknown>> = [];
  const visibleTextBelowFloor = () => page.evaluate(() => {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const tooSmall: Array<{ text: string; fontSize: string; selector: string }> = [];
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const text = node.textContent?.trim() ?? '';
      const parent = node.parentElement;
      if (!text || !parent || parent.closest('.sr-only,[aria-hidden="true"]') || parent.tagName === 'OPTION') continue;
      const style = getComputedStyle(parent);
      if (style.display === 'none' || style.visibility === 'hidden' || parent.getClientRects().length === 0) continue;
        if (Number.parseFloat(style.fontSize) < 14) tooSmall.push({ text: text.slice(0, 60), fontSize: style.fontSize, selector: `${parent.tagName.toLowerCase()}.${parent.className}` });
    }
    return tooSmall;
  });
  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const mainTitle = page.getByRole('heading', { name: '코드 보안 검사' });
    const typography = await page.evaluate(() => {
      const px = (selector: string) => {
        const element = document.querySelector(selector);
        return element ? Number.parseFloat(getComputedStyle(element).fontSize) : null;
      };
      const height = (selector: string) => {
        const element = document.querySelector(selector);
        return element ? Math.round(element.getBoundingClientRect().height) : null;
      };
      return {
        title: px('.workspace-title h1'), body: px('.workspace-title > p'), sidebar: px('.nav-item'),
        label: px('.control-label'), select: px('.mission-control select'), button: px('.run-button'),
        paragraphLineHeight: document.querySelector('.workspace-title > p') ? getComputedStyle(document.querySelector('.workspace-title > p')!).lineHeight : null,
        sidebarWidth: Math.round(document.querySelector('.workspace-sidebar')!.getBoundingClientRect().width),
        selectHeight: height('.mission-control select'), launchHeight: height('.run-button'),
        viewportWidth: document.documentElement.clientWidth, documentWidth: document.documentElement.scrollWidth,
      };
    });
    expect(typography.title).toBeGreaterThanOrEqual(30);
    expect(typography.body).toBeGreaterThanOrEqual(16);
    expect(typography.sidebar).toBeGreaterThanOrEqual(16);
    expect(typography.label).toBeGreaterThanOrEqual(16);
    expect(typography.select).toBeGreaterThanOrEqual(16);
    expect(typography.button).toBeGreaterThanOrEqual(17);
    expect(typography.selectHeight).toBeGreaterThanOrEqual(48);
    expect(typography.documentWidth).toBeLessThanOrEqual(typography.viewportWidth);
    samples.push({ viewport, typography });
    await expect(mainTitle).toBeVisible();
    expect(await visibleTextBelowFloor()).toEqual([]);
    await page.screenshot({ path: resolve(output, `start-${viewport.width}x${viewport.height}.png`), animations: 'disabled' });

    if (viewport.width <= 760) await page.getByRole('button', { name: '내비게이션 열기' }).click();
    await page.getByRole('button', { name: /사용 안내/ }).click();
    expect(await page.locator('.quick-start-content').evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(16);
    expect(await visibleTextBelowFloor()).toEqual([]);
    await page.screenshot({ path: resolve(output, `guide-${viewport.width}x${viewport.height}.png`), animations: 'disabled' });
    if (viewport.width <= 760) await page.getByRole('button', { name: '내비게이션 열기' }).click();
    await page.getByRole('button', { name: /검사 결과/ }).click();
    expect(await page.locator('.results-empty-state h2').evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(24);
    expect(await visibleTextBelowFloor()).toEqual([]);
    await page.screenshot({ path: resolve(output, `empty-results-${viewport.width}x${viewport.height}.png`), animations: 'disabled' });
    if (viewport.width <= 760) {
      await page.getByRole('button', { name: '내비게이션 열기' }).click();
      await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
      await page.screenshot({ path: resolve(output, `mobile-menu-${viewport.width}x${viewport.height}.png`), animations: 'disabled' });
      await page.getByRole('button', { name: '검사 시작', exact: true }).click();
    } else {
      await page.getByRole('button', { name: '검사 시작', exact: true }).click();
    }
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByLabel('로컬 API 토큰').fill('synthetic-large-type-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  expect(await visibleTextBelowFloor()).toEqual([]);
  expect(await page.locator('.row-main > strong').evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(16);
  expect(await page.locator('.filter-row input').evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(16);
  await page.screenshot({ path: resolve(output, 'completed-and-finding-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 720, height: 450 }); // 1440×900의 200% 확대 상황에 해당하는 좁은 CSS viewport 대체 확인
  const zoomLayout = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  expect(zoomLayout.content).toBeLessThanOrEqual(zoomLayout.viewport);
  expect(await page.locator('.workspace-title h1').evaluate((element) => Number.parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(30);
  expect(await visibleTextBelowFloor()).toEqual([]);
  samples.push({ viewport: { width: 720, height: 450, note: '200% 확대 대응 대체 CSS viewport; 실제 브라우저 확대 기능은 아님' }, zoomLayout });
  await writeFile(resolve(output, 'computed-style-samples.json'), JSON.stringify(samples, null, 2));
  await test.info().attach('large-type-computed-style-samples.json', { body: JSON.stringify(samples, null, 2), contentType: 'application/json' });
});

test('captures cyberpunk HUD launch, review, filtered, partial, and error states using synthetic data', async ({ page }) => {
  const output = resolve(process.cwd(), '../docs/assets/ui-large-type-readability-36-9b-z/regression-captures');
  await mkdir(output, { recursive: true });
  const token = 'phase-36-9b-synthetic-visual-token';
  const completed = {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 3, displayed_finding_count: 3, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 1, medium: 1, low: 1, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
    findings: [
      { finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/routes/route.js', line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
      { finding_id: 'semgrep:1123456789abcdef01234567', rule_id: 'synthetic.taint-example', severity: 'medium', verification_status: 'unverified', finding_kind: 'taint', file_path: 'src/controllers/example.js', line_number: 24, evidence_validation_status: 'validated', supported_claims: ['taint_rule_match_reported'], restricted_claims: [{ claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent'] }], validation_error_code: null },
      { finding_id: 'semgrep:2123456789abcdef01234567', rule_id: 'synthetic.html-example', severity: 'low', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/ui/Notice.tsx', line_number: 8, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
    ],
  };
  let nextResponse: typeof completed | { scan_status: string; completed: boolean; semgrep_version: string; finding_count: number; displayed_finding_count: number; omitted_finding_count: number; severity_counts: typeof completed.severity_counts; issues: string[]; limitations: string[]; findings: never[] } = completed;
  let failNext = false;
  let apiUnavailable = false;
  await page.route('**/api/v1/health', (route) => apiUnavailable ? route.abort() : route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => apiUnavailable ? route.abort() : route.fulfill({ json: {
    targets: [{ id: 'synthetic-review', label: '합성 검수 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: '기본 보안 규칙', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => failNext ? route.fulfill({ status: 503, json: { detail: 'synthetic unavailable' } }) : route.fulfill({ json: nextResponse }));
  await page.goto('/');
  const startDirectory = resolve(output, 'start');
  await mkdir(startDirectory, { recursive: true });
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: resolve(startDirectory, 'launch-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({ path: resolve(startDirectory, 'launch-1920x1080.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(startDirectory, 'launch-390x844.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByLabel('실제 검사 흐름')).toBeVisible();
  const launchMetrics = await page.evaluate(() => {
    const box = (selector: string) => {
      const element = document.querySelector(selector);
      if (!element) return null;
      const rect = element.getBoundingClientRect();
      return { top: Math.round(rect.top), height: Math.round(rect.height), bottom: Math.round(rect.bottom), width: Math.round(rect.width) };
    };
    const brief = document.querySelector('.launch-brief');
    const children = brief ? [...brief.querySelectorAll(':scope > *')] : [];
    const contentBottom = Math.max(...children.map((element) => element.getBoundingClientRect().bottom));
    return {
      viewport: { width: innerWidth, height: innerHeight },
      header: box('.topbar'), title: box('.workspace-title'), quickStart: box('.quick-start'),
      missionDeck: box('.mission-deck'), launchBrief: box('.launch-brief'),
      launchBriefContentBottom: Math.round(contentBottom),
      launchBriefBlankBelowContent: Math.round(brief!.getBoundingClientRect().bottom - contentBottom),
      focusableDecorativeDescendants: [...document.querySelectorAll('.launch-emblem svg button, .launch-emblem svg a, .launch-emblem svg [tabindex]')].length,
    };
  });
  expect(launchMetrics.missionDeck?.height).toBeLessThan(300);
  expect(launchMetrics.launchBrief?.height).toBeLessThan(240);
  expect(launchMetrics.launchBriefBlankBelowContent).toBeLessThan(40);
  expect(launchMetrics.focusableDecorativeDescendants).toBe(0);
  await writeFile(resolve(output, 'bounding-box-1440x900.json'), JSON.stringify(launchMetrics, null, 2));
  console.log('[Mission Control bounding boxes]', JSON.stringify(launchMetrics));
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();

  for (const viewport of [
    { width: 1920, height: 1080, name: 'completed-1920x1080' },
    { width: 1440, height: 900, name: 'completed-1440x900' },
    { width: 1280, height: 800, name: 'completed-1280x800' },
    { width: 768, height: 1024, name: 'completed-768x1024' },
    { width: 390, height: 844, name: 'completed-390x844' },
  ]) {
    await page.setViewportSize(viewport);
    await page.screenshot({ path: resolve(output, `${viewport.name}.png`), animations: 'disabled' });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('.detail-panel').evaluate((element) => { element.scrollTop = 0; });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.locator('.detail-panel').screenshot({ path: resolve(output, 'finding-detail-panel.png'), animations: 'disabled' });
  await page.getByLabel('심각도').selectOption('high');
  await page.screenshot({ path: resolve(output, 'filtered-high.png'), animations: 'disabled' });
  await page.getByLabel('심각도').selectOption('all');
  await page.getByText('기술 근거와 제한 자세히 보기').click();
  await page.getByLabel('선택한 Finding 상세').evaluate((element) => { element.scrollTop = element.scrollHeight; });
  await page.screenshot({ path: resolve(output, 'finding-detail-1440x900.png'), animations: 'disabled' });

  nextResponse = {
    scan_status: 'partial', completed: false, semgrep_version: '1.182.1', finding_count: 0, displayed_finding_count: 0, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_partial', 'scan_result_is_not_safety_proof'], findings: [],
  };
  await page.getByRole('button', { name: '검사 시작', exact: true }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '부분 검사' })).toBeVisible();
  await page.screenshot({ path: resolve(output, 'partial-zero-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(output, 'partial-zero-390x844.png'), animations: 'disabled' });
  failNext = true;
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: '검사 시작', exact: true }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('alert')).toContainText('요청이 거부되었습니다');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: resolve(output, 'request-error-1440x900.png'), animations: 'disabled' });
  apiUnavailable = true;
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('검사 서버를 실행하고');
  await expect(page.getByRole('combobox', { name: '검사 대상' })).toBeDisabled();
  await expect(page.getByRole('option', { name: '서버 연결 후 목록을 불러옵니다' })).toHaveCount(2);
  await page.screenshot({ path: resolve(output, 'api-offline-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(output, 'api-offline-390x844.png'), animations: 'disabled' });
  apiUnavailable = false;
  await page.getByRole('button', { name: '다시 연결' }).click();
  await expect(page.getByText('옵션 불러옴')).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('sidebar navigation separates start, current-session results, and guidance and supports the mobile drawer', async ({ page }) => {
  const output = resolve(process.cwd(), '../docs/assets/ui-large-type-readability-36-9b-z/navigation-audit');
  await mkdir(output, { recursive: true });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-review', label: '합성 검수 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: '기본 보안 규칙', experimental: false }],
  } }));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 900 });
  const desktopMetrics = await page.evaluate(() => {
    const rect = (selector: string) => { const box = document.querySelector(selector)?.getBoundingClientRect(); return box ? { x: Math.round(box.x), y: Math.round(box.y), width: Math.round(box.width), height: Math.round(box.height) } : null; };
    return { viewport: { width: innerWidth, height: innerHeight }, sidebar: rect('.workspace-sidebar'), main: rect('.dashboard-main'), bodyText: getComputedStyle(document.querySelector('.workspace-title > p')!).fontSize, inputHeight: rect('.mission-control select')?.height ?? 0, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth };
  });
  expect(desktopMetrics.sidebar?.width).toBeGreaterThanOrEqual(232);
  expect(desktopMetrics.sidebar?.width).toBeLessThanOrEqual(256);
  expect(Number.parseFloat(desktopMetrics.bodyText)).toBeGreaterThanOrEqual(14);
  expect(desktopMetrics.inputHeight).toBeGreaterThanOrEqual(48);
  expect(desktopMetrics.overflow).toBe(0);
  await page.screenshot({ path: resolve(output, 'start-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({ path: resolve(output, 'start-1920x1080.png'), animations: 'disabled' });
  await writeFile(resolve(output, 'desktop-metrics-1440x900.json'), JSON.stringify(desktopMetrics, null, 2));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: '검사 결과' }).click();
  await expect(page.getByRole('heading', { name: '이 세션에는 검사 결과가 없습니다' })).toBeVisible();
  await page.screenshot({ path: resolve(output, 'results-empty-1440x900.png'), animations: 'disabled' });
  await page.getByRole('button', { name: '사용 안내' }).click();
  await expect(page.getByText('보안 분석 용어 쉽게 보기')).toBeVisible();
  await page.screenshot({ path: resolve(output, 'guide-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole('button', { name: '사이드바 접기' }).click();
  await page.screenshot({ path: resolve(output, 'sidebar-collapsed-1440x900.png'), animations: 'disabled' });
  await page.getByRole('button', { name: '사이드바 펼치기' }).click();
  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByLabel('로컬 API 토큰').fill('synthetic-sidebar-visual-token');
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], limitations: ['scan_result_is_not_safety_proof'],
    findings: [{ finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/sample.py', line_number: 8, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null }],
  } }));
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.screenshot({ path: resolve(output, 'results-1440x900.png'), animations: 'disabled' });
  await page.screenshot({ path: resolve(output, 'finding-detail-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  const menu = page.getByRole('button', { name: '내비게이션 열기' });
  await menu.click();
  await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
  await page.screenshot({ path: resolve(output, 'mobile-drawer-390x844.png'), animations: 'disabled' });
  await page.keyboard.press('Escape');
  await expect(menu).toHaveAttribute('aria-expanded', 'false');
  await expect(menu).toBeFocused();
  await menu.click();
  await page.getByRole('button', { name: '검사 시작' }).click();
  await expect(page.getByLabel('검사 대상')).toBeVisible();
});
