import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

function finding(id: string) {
  return { finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: `baseline.rule-${id}`, severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/${id}.js`, line_number: 4, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null };
}
function scan(findings: ReturnType<typeof finding>[]) {
  return { scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'] };
}

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
  await page.getByRole('button', { name: '비교 기준으로 지정' }).click();
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

  await page.getByLabel('분석가 검토 상태').selectOption('pending');
  await expect(list.getByRole('button')).toHaveCount(1);
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('현재 선택한 항목은 필터에서 제외되었습니다');
  await page.getByLabel('분석가 검토 상태').selectOption('all');
  await list.getByRole('button', { name: /rule-cccccccc/ }).click();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('pending');
  await list.getByRole('button', { name: /rule-aaaaaaaa/ }).click();
  await expect(note).toHaveValue('<img src=x onerror=alert(1)> analyst note');

  const confirmation = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  await page.getByRole('button', { name: '검사 시작' }).click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await confirmation;
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('분석가 검토 상태')).toHaveValue('all');
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
