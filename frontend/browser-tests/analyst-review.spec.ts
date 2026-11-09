import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';

function finding(id: string) {
  return { finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: `baseline.rule-${id}`, severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/${id}.js`, line_number: 4, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null };
}
function scan(findings: ReturnType<typeof finding>[]) {
  const severity_counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of findings) severity_counts[item.severity as keyof typeof severity_counts] += 1;
  return { scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'] };
}

test('검토 가이드 합성 화면: High validated, High rejected, Medium validated와 모바일 폭', async ({ page }) => {
  let current = { ...finding('aaaaaaaaaaaaaaaaaaaaaaaa'), rule_id: 'baseline.javascript-dynamic-eval' };
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: 'Synthetic Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scan([current]) }));
  const evidenceDir = resolve(process.cwd(), '../docs/assets/phase8k');
  await mkdir(evidenceDir, { recursive: true });

  async function capture(name: string, width = 1440, height = 900) {
    await page.setViewportSize({ width, height });
    await page.goto('/');
    await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
    await page.getByRole('button', { name: '검사 실행' }).click();
    await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
    const guide = page.getByLabel('선택한 Finding 상세').getByRole('region', { name: '분석가 검토 가이드' });
    await guide.getByText('판단 근거, 단계별 검토 절차 및 권장 조치').click();
    await expect(guide.getByText(/고려할 조치 방향/)).toBeVisible();
    await page.screenshot({ path: resolve(evidenceDir, name), fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), `horizontal overflow at ${width}px`).toBe(true);
  }

  await capture('triage-high-validated-1440.png');
  current = { ...current, finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', severity: 'medium', evidence_validation_status: 'validated' };
  await capture('triage-medium-validated-1440.png');
  current = { ...current, finding_id: 'semgrep:cccccccccccccccccccccccc', severity: 'high', evidence_validation_status: 'rejected' };
  await capture('triage-high-rejected-1440.png');
  current = { ...current, finding_id: 'semgrep:dddddddddddddddddddddddd', evidence_validation_status: 'validated' };
  await capture('triage-high-validated-390.png', 390, 844);
  for (const width of [1920, 1536, 1440, 1280, 1024, 768, 600, 390, 320]) {
    await page.setViewportSize({ width, height: width <= 600 ? 844 : 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), `horizontal overflow at ${width}px`).toBe(true);
  }
});

test('상세 검토 가이드는 심각도와 근거 연결 상태를 구분하고 검토 상태와 독립적으로 동작한다', async ({ page }) => {
  const highRejected = { ...finding('aaaaaaaaaaaaaaaaaaaaaaaa'), rule_id: 'baseline.javascript-dynamic-eval', evidence_validation_status: 'rejected' };
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: 'Synthetic Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: scan([highRejected]) }));
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  const detail = page.getByLabel('선택한 Finding 상세');
  const guide = detail.getByRole('region', { name: '분석가 검토 가이드' });
  await expect(guide).toContainText('근거 연결 확인 필요');
  await expect(guide).toContainText('높음');
  await expect(guide).toContainText('위험도가 낮다는 뜻은 아닙니다');
  await guide.getByText('판단 근거, 단계별 검토 절차 및 권장 조치').click();
  await expect(guide).toContainText('new Function');
  await expect(guide).toContainText('JSON 파싱');
  await detail.getByLabel('수동 검토 상태').selectOption('reviewed');
  await expect(guide).toContainText('근거 연결 확인 필요');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
});

test('Finding 검토 상태와 메모는 현재 검사에 격리되고 확인·필터·내보내기·새로고침 동작을 지킨다', async ({ page }) => {
  let scans = 0;
  let scanRequests = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: 'Synthetic Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => {
    scanRequests += 1;
    const response = scans++ === 0 ? scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa'), finding('bbbbbbbbbbbbbbbbbbbbbbbb')]) : scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa'), finding('cccccccccccccccccccccccc')]);
    return route.fulfill({ json: response });
  });

  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByRole('button', { name: /비교 기준/ }).click();
  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();

  const list = page.getByRole('region', { name: 'Finding 목록' });
  const firstFinding = list.getByRole('button', { name: /rule-aaaaaaaa/ });
  await firstFinding.focus();
  await page.keyboard.press('Enter');
  const note = page.getByLabel('분석가 메모');
  await note.fill('<img src=x onerror=alert(1)> analyst note');
  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await expect(page.locator('img')).toHaveCount(0);
  await expect(list).toContainText('분석가: 검토 완료');
  expect(scanRequests).toBe(2);

  await page.getByRole('combobox', { name: '분석가 검토' }).selectOption('pending');
  await expect(list.getByRole('button')).toHaveCount(1);
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('현재 선택한 항목은 필터에서 제외되었습니다');
  await page.getByRole('combobox', { name: '분석가 검토' }).selectOption('all');
  await list.getByRole('button', { name: /rule-cccccccc/ }).click();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('pending');
  await list.getByRole('button', { name: /rule-aaaaaaaa/ }).click();
  await expect(note).toHaveValue('<img src=x onerror=alert(1)> analyst note');

  const confirmation = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await confirmation;
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByRole('combobox', { name: '분석가 검토' })).toHaveValue('all');
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('검토 대기');
  expect(scanRequests).toBe(3);

  const updatedList = page.getByRole('region', { name: 'Finding 목록' });
  await updatedList.getByRole('button', { name: /rule-aaaaaaaa/ }).click();
  await page.getByLabel('분석가 메모').fill('note should stay out of exported reports');
  const currentReport = page.waitForEvent('download');
  await page.getByRole('button', { name: '현재 검사 결과 내보내기' }).click();
  const currentDownload = await currentReport;
  const currentMarkdown = await readFile((await currentDownload.path())!, 'utf8');
  expect(currentMarkdown).not.toContain('note should stay out of exported reports');
  expect(currentMarkdown).not.toContain('synthetic-review-token');
  const compareSummary = page.getByText('검사 결과 비교');
  await compareSummary.click();
  const comparisonReport = page.waitForEvent('download');
  await page.getByRole('button', { name: '비교 보고서 내보내기' }).click();
  const comparisonDownload = await comparisonReport;
  const comparisonMarkdown = await readFile((await comparisonDownload.path())!, 'utf8');
  expect(comparisonMarkdown).not.toContain('note should stay out of exported reports');
  expect(comparisonMarkdown).not.toContain('synthetic-review-token');
  expect(scanRequests).toBe(3);

  await page.reload();
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await expect(page.getByLabel('로컬 API 토큰')).toHaveValue('');
  await expect(page.getByLabel('분석가 메모')).toHaveCount(0);

  await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('분석가 메모')).toHaveValue('');
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('pending');
  for (const [width, height] of [[1920, 1080], [1440, 900], [1024, 768], [768, 1024], [390, 844], [320, 800]]) {
    await page.setViewportSize({ width, height });
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(dimensions.client);
  }
});

test('새 검사 경고를 닫으면 검토 기록을 유지하고 키보드로 기존 JSON 백업에 도달한다', async ({ page }) => {
  let scanRequests = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: 'Synthetic Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => { scanRequests += 1; return route.fulfill({ json: scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa')]) }); });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByLabel('분석가 메모').fill('dismissed warning keeps this note');

  const warning = page.waitForEvent('dialog').then(async (dialog) => { const text = dialog.message(); await dialog.dismiss(); return text; });
  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByRole('button', { name: '검사 실행' }).press('Enter');
  expect(await warning).toContain('검토 기록 백업 JSON 다운로드');
  const backupButton = page.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' });
  await expect(backupButton).toBeFocused();
  await expect(page.getByLabel('분석가 메모')).toHaveValue('dismissed warning keeps this note');
  const backup = page.waitForEvent('download');
  await page.keyboard.press('Enter');
  const backupJson = JSON.parse(await readFile((await (await backup).path())!, 'utf8'));
  expect(backupJson.findings[0]).toMatchObject({ finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', review_status: 'pending' });
  expect(scanRequests).toBe(1);
  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations).toEqual([]);
});

test('실패·부분 재검사는 이전 결과와 검토 기록을 유지하고 정상 완료 재검사만 기록을 지운다', async ({ page }) => {
  const replies: Array<'abort' | object> = [
    scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa')]),
    'abort',
    { ...scan([finding('bbbbbbbbbbbbbbbbbbbbbbbb')]), scan_status: 'partial', completed: false },
    scan([finding('aaaaaaaaaaaaaaaaaaaaaaaa')]),
  ];
  let scanRequests = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: 'Synthetic Project' }], rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => {
    scanRequests += 1;
    const next = replies.shift();
    return next === 'abort' ? route.abort('connectionrefused') : route.fulfill({ json: next });
  });
  const dialogs: string[] = [];
  page.on('dialog', (dialog) => { dialogs.push(dialog.message()); void dialog.accept(); });
  const results = page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ });
  const retainedNote = page.getByText(/마지막 새 검사 결과는 적용되지 않았습니다/);
  const rescan = async () => {
    await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 시작' }).click();
    await page.getByRole('button', { name: '검사 실행' }).click();
  };

  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByLabel('수동 검토 상태').selectOption('needs_followup');
  await page.getByLabel('분석가 메모').fill('failed rescan must keep this note');

  await rescan();
  await expect(page.locator('.request-feedback')).toContainText('이전 검사 결과와 분석가 검토 기록을 그대로 유지했습니다');
  await results.click();
  await expect(retainedNote).toBeVisible();
  await expect(page.getByLabel('분석가 메모')).toHaveValue('failed rescan must keep this note');
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('needs_followup');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  await rescan();
  await expect(page.locator('.request-feedback')).toContainText('부분 검사로 끝나 결과를 적용하지 않았습니다');
  await expect(retainedNote).toBeVisible();
  await expect(page.getByRole('region', { name: 'Finding 목록' })).not.toContainText('baseline.rule-bbbbbbbbbbbbbbbbbbbbbbbb');
  await expect(page.getByLabel('분석가 메모')).toHaveValue('failed rescan must keep this note');

  await rescan();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(retainedNote).toHaveCount(0);
  await expect(page.getByLabel('분석가 메모')).toHaveValue('');
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('pending');
  expect(dialogs).toHaveLength(3);
  for (const text of dialogs) expect(text).toContain('실패하거나 일부만 완료되면 새 결과를 적용하지 않고 이전 결과와 기록을 유지');
  expect(scanRequests).toBe(4);
});
