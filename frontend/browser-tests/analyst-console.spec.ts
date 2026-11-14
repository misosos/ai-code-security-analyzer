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

async function openResults(page: Page, body: object = scan) {
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: options }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: body }));
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

for (const width of [1440, 390, 320]) {
  test(`token storage note opens in the document flow without covering the content below at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
    await page.route('**/api/v1/options', (route) => route.fulfill({ json: options }));
    await page.goto('/');
    const disclosure = page.locator('.token-security-help');
    const runButtonTopClosed = await page.getByRole('button', { name: '검사 실행' }).evaluate((el) => el.getBoundingClientRect().top + scrollY);
    await disclosure.locator('summary').focus();
    await page.keyboard.press('Enter');
    await expect(disclosure).toHaveAttribute('open', '');
    await expect(disclosure.locator('p')).toContainText('토큰은 브라우저 메모리에만 보관되고 요청 헤더로 전송됩니다.');
    const layout = await page.evaluate(() => {
      const note = document.querySelector('.token-security-help > p')!;
      const box = note.getBoundingClientRect();
      const covered = [...document.querySelectorAll('body *')].filter((el) => {
        if (el === note || el.contains(note) || note.contains(el)) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && r.left < box.right - 1 && r.right > box.left + 1 && r.top < box.bottom - 1 && r.bottom > box.top + 1;
      }).map((el) => el.className);
      return { position: getComputedStyle(note).position, covered, clipped: note.scrollHeight - note.clientHeight, overflow: document.documentElement.scrollWidth - innerWidth };
    });
    expect(layout.position).toBe('static');
    expect(layout.covered).toEqual([]);
    expect(layout.clipped).toBeLessThanOrEqual(0);
    expect(layout.overflow).toBeLessThanOrEqual(0);
    if (width < 1100) {
      // In the stacked layout the run button sits below the note and must move down when it opens.
      const runButtonTopOpen = await page.getByRole('button', { name: '검사 실행' }).evaluate((el) => el.getBoundingClientRect().top + scrollY);
      expect(runButtonTopOpen).toBeGreaterThan(runButtonTopClosed);
    }
    await page.keyboard.press('Enter');
    await expect(disclosure).not.toHaveAttribute('open', '');
  });
}

test('evidence linkage is shown apart from analyst review and never as a green check', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  await expect(page.locator('.finding-table-head')).toContainText('근거');
  const row = page.getByLabel('Finding 목록').getByRole('button').first();
  await expect(row).toContainText('분석가: 검토 대기');
  await expect(row).toContainText('근거 연결 구조 확인');
  const icon = row.locator('.validation-icon.validated');
  await expect(icon).toHaveAttribute('title', '근거 연결 구조 확인');
  await expect(icon).toHaveAttribute('aria-hidden', 'true');
  await expect(icon.locator('path[d="m5 12 4 4L19 6"]')).toHaveCount(0);
  const colors = await page.evaluate(() => {
    const probe = document.createElement('span');
    probe.style.color = 'var(--success)';
    document.querySelector('.app-shell')!.append(probe);
    const success = getComputedStyle(probe).color;
    probe.style.color = 'var(--accent)';
    const accent = getComputedStyle(probe).color;
    probe.remove();
    const evidence = getComputedStyle(document.querySelector('.finding-row .validation-icon.validated')!).color;
    return { success, accent, evidence };
  });
  expect(colors.evidence).not.toBe(colors.success);
  expect(colors.evidence).not.toBe(colors.accent);
});

test('choosing another finding shows the top of its detail even after the panel was scrolled', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  const rows = page.getByLabel('Finding 목록').getByRole('button');
  const panel = page.locator('.results-layout > .detail-panel');
  await panel.evaluate((el) => { el.scrollTop = el.scrollHeight; });
  expect(await panel.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
  await rows.nth(2).click();
  await expect(panel).toContainText('src/module2/handler.ts:12');
  expect(await panel.evaluate((el) => el.scrollTop)).toBe(0);
  const top = await panel.locator('.detail-top').evaluate((el) => el.getBoundingClientRect().top);
  expect(top).toBeGreaterThanOrEqual(0);
  // The panel still scrolls so the evidence and review inputs stay reachable.
  await panel.evaluate((el) => { el.scrollTop = el.scrollHeight; });
  expect(await panel.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
  await expect(page.locator('#analyst-note')).toBeVisible();
});

const mixedEvidenceScan = {
  ...scan,
  findings: [scan.findings[0], { ...scan.findings[1], evidence_validation_status: 'rejected', supported_claims: [], restricted_claims: [], validation_error_code: 'evidence_unavailable' }, scan.findings[2]],
};

/** Where the last block of the open detail sits, against both the panel's visible box and the window. */
async function detailEnd(page: Page) {
  return page.locator('.results-layout > .detail-panel').evaluate((panel) => {
    const last = panel.querySelector('article')!.lastElementChild!.getBoundingClientRect();
    const box = panel.getBoundingClientRect();
    const visibleTop = Math.max(0, box.top);
    const visibleBottom = Math.min(innerHeight, box.bottom);
    return {
      scrollHeight: panel.scrollHeight, clientHeight: panel.clientHeight, scrollTop: panel.scrollTop,
      atMax: panel.scrollTop >= panel.scrollHeight - panel.clientHeight - 1,
      lastVisible: last.height > 0 && last.top >= visibleTop - 1 && last.bottom <= visibleBottom + 1,
    };
  });
}

for (const [width, height] of [[1440, 900], [1280, 800]] as const) {
  test(`detail panel can be read to its last block with the mouse wheel at ${width}x${height}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await openResults(page);
    const panel = page.locator('.results-layout > .detail-panel');
    const start = await detailEnd(page);
    expect(start.scrollHeight).toBeGreaterThan(start.clientHeight);
    const box = (await panel.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + 40);
    for (let step = 0; step < 30; step++) await page.mouse.wheel(0, 300);
    await expect.poll(async () => (await detailEnd(page)).atMax).toBe(true);
    await expect.poll(async () => (await detailEnd(page)).lastVisible).toBe(true);
  });
}

test('detail panel can be read to its last block with the keyboard', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  const panel = page.locator('.results-layout > .detail-panel');
  await panel.focus();
  for (let step = 0; step < 12; step++) await page.keyboard.press('PageDown');
  await expect.poll(async () => (await detailEnd(page)).atMax).toBe(true);
  await expect.poll(async () => (await detailEnd(page)).lastVisible).toBe(true);
});

test('after reading to the end, a new selection or a filter change opens the next detail at its title', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  const panel = page.locator('.results-layout > .detail-panel');
  const titleInView = () => panel.locator('.detail-top h2').evaluate((el) => { const r = el.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; });
  const box = (await panel.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + 40);
  for (let step = 0; step < 30; step++) await page.mouse.wheel(0, 300);
  await expect.poll(async () => (await detailEnd(page)).lastVisible).toBe(true);

  await page.getByLabel('Finding 목록').getByRole('button').nth(1).click();
  await expect(panel).toContainText('src/module1/handler.ts:11');
  expect(await panel.evaluate((el) => el.scrollTop)).toBe(0);
  expect(await titleInView()).toBe(true);

  // A filter that hides the selected finding says so in view; picking a remaining finding opens it at its title.
  await panel.evaluate((el) => { el.scrollTop = el.scrollHeight; });
  await page.getByLabel('심각도', { exact: true }).selectOption('medium');
  await expect(panel.locator('.select-prompt')).toBeInViewport();
  await page.getByLabel('Finding 목록').getByRole('button').first().click();
  await expect(panel).toContainText('src/module2/handler.ts:12');
  expect(await panel.evaluate((el) => el.scrollTop)).toBe(0);
  expect(await titleInView()).toBe(true);
});

for (const [width, height] of [[1440, 900], [1280, 800], [1024, 768], [768, 1024], [390, 844], [320, 640]] as const) {
  test(`filter values and labels are not cut off at ${width}x${height}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await openResults(page);
    for (const [name, value] of [['탐지 유형', 'pattern'], ['탐지 유형', 'taint'], ['탐지 유형', 'unclassified'], ['분석가 검토', 'needs_followup'], ['검증 상태', 'unverified']] as const) {
      await page.getByLabel(name, { exact: true }).selectOption(value);
      const fit = await page.getByLabel(name, { exact: true }).evaluate((select: HTMLSelectElement) => {
        const style = getComputedStyle(select);
        const context = document.createElement('canvas').getContext('2d')!;
        context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
        const text = select.options[select.selectedIndex].text;
        const room = select.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        const label = select.closest('label')!.querySelector('span')!;
        return { text, textWidth: context.measureText(text).width, room, fontSize: parseFloat(style.fontSize), labelCut: label.scrollWidth > label.clientWidth + 1 };
      });
      expect(fit.textWidth, `${name}=${fit.text}`).toBeLessThanOrEqual(fit.room);
      expect(fit.fontSize).toBeGreaterThanOrEqual(16);
      expect(fit.labelCut, `${name} label`).toBe(false);
    }
    await page.getByLabel('탐지 유형', { exact: true }).selectOption('all');
    await page.getByLabel('분석가 검토', { exact: true }).selectOption('all');
    await page.getByLabel('검증 상태', { exact: true }).selectOption('all');
    await expect(page.getByLabel('Finding 목록').getByRole('button')).toHaveCount(3);
    await page.getByLabel('탐지 유형', { exact: true }).selectOption('taint');
    await expect(page.getByLabel('Finding 목록').getByRole('button')).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
  });
}

for (const width of [1440, 390, 320]) {
  test(`evidence linkage state is written out next to the review state at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await openResults(page, mixedEvidenceScan);
    const rows = page.getByLabel('Finding 목록').getByRole('button');
    await expect(rows.nth(0).locator('.evidence-validation-label')).toBeVisible();
    await expect(rows.nth(0).locator('.evidence-validation-label')).toHaveText('근거 연결 구조 확인');
    await expect(rows.nth(1).locator('.evidence-validation-label')).toBeVisible();
    await expect(rows.nth(1).locator('.evidence-validation-label')).toHaveText('근거 연결 확인 불가');
    // Visible on screen, not only to screen readers: no ancestor up to the row collapses or clips the label.
    for (const index of [0, 1]) {
      const shown = await rows.nth(index).locator('.evidence-validation-label').evaluate((label) => {
        for (let node: Element | null = label; node && !node.classList.contains('finding-row'); node = node.parentElement) {
          const rect = node.getBoundingClientRect();
          const style = getComputedStyle(node);
          if (rect.width <= 1 || rect.height <= 1 || style.clip !== 'auto' || style.opacity === '0') return false;
        }
        return true;
      });
      expect(shown, `row ${index} evidence label is drawn`).toBe(true);
    }
    // One accessible name holds the review state, the evidence state and that the finding is unconfirmed, each once.
    const name = await rows.nth(0).evaluate((row) => row.textContent ?? '');
    expect(name).toContain('분석가: 검토 대기');
    expect(name).toContain('미확인 후보');
    expect(name.split('근거 연결 구조 확인').length - 1).toBe(1);
    await expect(rows.nth(0).locator('.validation-icon')).toHaveAttribute('aria-hidden', 'true');
    const review = await rows.nth(0).locator('.analyst-review-badge').boundingBox();
    const evidence = await rows.nth(0).locator('.evidence-validation-label').boundingBox();
    // Desktop: one status column, labels on one start line. Phone: evidence gets its own line below the location.
    if (width > 760) expect(Math.abs(review!.x - evidence!.x), 'labels share one start line').toBeLessThanOrEqual(1);
    expect(evidence!.y).toBeGreaterThan(review!.y);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
  });
}

for (const width of [1440, 390, 320]) {
  test(`backup file picker matches the console and shows the chosen file at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await openResults(page);
    await page.locator('details.analyst-backup-tool > summary').click();
    const input = page.getByLabel('검토 기록 불러오기(JSON)');
    const button = page.locator('.backup-file-button');
    const status = page.locator('#backup-file-status');
    await expect(button).toBeVisible();
    await expect(button).toHaveText('JSON 파일 선택');
    await expect(status).toHaveText('선택한 파일 없음');
    await expect(input).toHaveAttribute('type', 'file');
    await expect(input).toHaveAttribute('aria-describedby', /backup-file-status/);
    // Tab from the download button reaches the real input, and the visible button shows the focus.
    await page.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).focus();
    await page.keyboard.press('Tab');
    await expect(input).toBeFocused();
    await expect(button).toHaveCSS('outline-style', 'solid');
    // Clicking the visible button opens the real file chooser.
    const chooser = page.waitForEvent('filechooser');
    await button.click();
    const longName = `analyst-review-backup-${'very-long-file-name-segment-'.repeat(4)}final.json`;
    await (await chooser).setFiles({ name: longName, mimeType: 'application/json', buffer: Buffer.from('{broken') });
    // The existing sanitizer keeps at most 128 characters of the name.
    await expect(status).toHaveText(`선택한 파일: ${longName.slice(0, 128)}`);
    await expect(page.locator('.analyst-backup-controls [role="status"]')).toBeVisible();
    const fit = await page.evaluate(() => {
      const name = document.querySelector('#backup-file-status')!.getBoundingClientRect();
      const box = document.querySelector('.analyst-backup-controls')!.getBoundingClientRect();
      return { right: name.right, boxRight: box.right, overflow: document.documentElement.scrollWidth - innerWidth };
    });
    expect(fit.right).toBeLessThanOrEqual(fit.boxRight + 1);
    expect(fit.overflow).toBeLessThanOrEqual(0);
  });
}

/** WCAG contrast of an element's text against the first opaque background behind it. */
async function textContrast(page: Page, selector: string) {
  return page.locator(selector).first().evaluate((element) => {
    const channels = (value: string) => (value.match(/[\d.]+/g) ?? []).map(Number);
    const luminance = ([r, g, b]: number[]) => [r, g, b].map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }).reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
    let background = [0, 0, 0];
    for (let node: Element | null = element; node; node = node.parentElement) {
      const color = channels(getComputedStyle(node).backgroundColor);
      if (color.length >= 3 && (color[3] ?? 1) > 0) { background = color; break; }
    }
    const style = getComputedStyle(element);
    const [a, b] = [luminance(channels(style.color)), luminance(background)];
    return { ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05), size: parseFloat(style.fontSize), weight: Number(style.fontWeight) };
  });
}

test('analyst review labels read first and their help stays readable', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openResults(page);
  const editor = '.results-layout > .detail-panel .analyst-review-editor';
  const heading = await textContrast(page, `${editor} h3`);
  const statusLabel = await textContrast(page, `${editor} label:has(select)`);
  const noteLabel = await textContrast(page, `${editor} label[for="analyst-note"]`);
  const help = await textContrast(page, `${editor} .analyst-note-help`);
  const count = await textContrast(page, `${editor} .analyst-note-count`);
  for (const [name, label] of [['수동 검토 상태', statusLabel], ['분석가 메모', noteLabel]] as const) {
    expect(label.size, `${name} size`).toBeGreaterThanOrEqual(16);
    expect(label.weight, `${name} weight`).toBeGreaterThanOrEqual(500);
    expect(label.ratio, `${name} contrast`).toBeGreaterThanOrEqual(7);
  }
  expect(help.size).toBeGreaterThanOrEqual(16);
  expect(help.ratio).toBeGreaterThanOrEqual(7);
  expect(count.ratio).toBeGreaterThanOrEqual(4.5);
  // Hierarchy: heading clearly larger than labels; labels heavier than values; values heavier than help.
  expect(heading.size).toBeGreaterThanOrEqual(statusLabel.size + 4);
  expect(help.size).toBeGreaterThan(count.size);
  for (const control of [`${editor} select`, `${editor} textarea`]) {
    const value = await textContrast(page, control);
    expect(value.size, `${control} size`).toBeGreaterThanOrEqual(16);
    expect(value.weight, `${control} weight`).toBeGreaterThanOrEqual(500);
    expect(value.ratio, `${control} contrast`).toBeGreaterThanOrEqual(7);
    expect(statusLabel.weight, 'labels heavier than values').toBeGreaterThan(value.weight);
    expect(value.weight, 'values heavier than help').toBeGreaterThan(help.weight);
  }
  // The selected value has room for a full line of text, so it is not shrunk or clipped.
  const room = await page.locator(`${editor} select`).evaluate((select) => {
    const style = getComputedStyle(select);
    return { content: select.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom), line: parseFloat(style.fontSize) * 1.2 };
  });
  expect(room.content).toBeGreaterThanOrEqual(room.line);
  // Labels still name their controls.
  await expect(page.getByLabel('수동 검토 상태')).toBeVisible();
  await expect(page.getByLabel('분석가 메모')).toBeVisible();
});

const allDecisionsScan = {
  ...scan,
  findings: [{ ...scan.findings[0], restricted_claims: [
    { claim_type: 'taint_rule_match_reported', decision: 'unavailable', reason_codes: [] },
    { claim_type: 'source_location_identified', decision: 'insufficient_evidence', reason_codes: [] },
    { claim_type: 'flow_trace_available', decision: 'ambiguous', reason_codes: [] },
    { claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] },
  ] }, scan.findings[1], scan.findings[2]],
};

for (const width of [1440, 1024, 768, 390, 320]) {
  test(`each unconfirmed claim keeps a gap between its title and its status at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await openResults(page, allDecisionsScan);
    // The claims live in the technical disclosure; open it the way a user does.
    const disclosure = page.locator('.detail-panel .technical-details');
    await disclosure.locator('summary').focus();
    await page.keyboard.press('Enter');
    await expect(disclosure).toHaveAttribute('open', '');
    const items = page.locator('.detail-panel .claim-section.restricted li');
    await expect(items.first()).toBeVisible();
    await expect(items).toHaveCount(4);
    await expect(items.nth(0)).toContainText('현재 자료에서 확인 불가');
    await expect(items.nth(1)).toContainText('근거 부족');
    await expect(items.nth(2)).toContainText('근거 연결 모호');
    await expect(items.nth(3)).toContainText('이 분석에서 지원하지 않는 판단');
    const layout = await items.evaluateAll((list) => list.map((item) => {
      const title = item.querySelector('strong')!;
      const status = item.querySelector('.decision')!;
      // Line boxes of each piece of text, so a wrapped title is measured by its last line.
      const titleLines = [...title.getClientRects()];
      const statusLines = [...status.getClientRects()];
      const lastTitle = titleLines[titleLines.length - 1];
      const firstStatus = statusLines[0];
      const box = item.getBoundingClientRect();
      // Same line when the two line boxes overlap vertically (title and status are baseline-aligned at different sizes).
      const sameLine = firstStatus.top < lastTitle.bottom && firstStatus.bottom > lastTitle.top;
      const overlap = titleLines.some((t) => statusLines.some((s) => t.left < s.right - 0.5 && t.right > s.left + 0.5 && t.top < s.bottom - 0.5 && t.bottom > s.top + 0.5));
      return {
        text: item.textContent, sameLine, overlap,
        gap: sameLine ? firstStatus.left - lastTitle.right : firstStatus.top - lastTitle.bottom,
        inside: [...titleLines, ...statusLines].every((r) => r.left >= box.left - 1 && r.right <= box.right + 1),
      };
    }));
    for (const item of layout) {
      expect(item.overlap, item.text ?? '').toBe(false);
      expect(item.inside, item.text ?? '').toBe(true);
      if (item.sameLine) {
        expect(item.gap, `${item.text} horizontal gap`).toBeGreaterThanOrEqual(8);
        expect(item.gap, `${item.text} horizontal gap`).toBeLessThanOrEqual(16);
      } else {
        expect(item.gap, `${item.text} wrapped below`).toBeGreaterThanOrEqual(0);
      }
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
  });
}
