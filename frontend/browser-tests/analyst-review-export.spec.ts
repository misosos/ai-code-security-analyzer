import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const finding = (id: string) => ({ finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: `baseline.rule-${id}`, severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/${id}.ts`, line_number: 9, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null });
const findings = [finding('aaaaaaaa'), finding('bbbbbbbb')];
const response = { scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 2, displayed_finding_count: 2, omitted_finding_count: 0, severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'] };

test('분석가 보고서는 기본 메모 제외, 별도 확인 후 전체 Finding 메모를 다운로드한다', async ({ page }) => {
  let scans = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: '합성 프로젝트' }], rule_profiles: [{ id: 'baseline', label: '기본 규칙', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => { scans += 1; return route.fulfill({ json: response }); });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-review-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  const disclosure = page.getByText('분석가 검토 기록 내보내기', { exact: true });
  await disclosure.focus();
  await page.keyboard.press('Enter');

  await page.getByLabel('분석가 메모').fill('private analyst note <script>alert(1)</script>');
  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await page.getByRole('searchbox', { name: '검색' }).fill('aaaaaaaa');
  await expect(page.getByLabel('Finding 목록').getByRole('button')).toHaveCount(1);

  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  const withoutNotesPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '분석가 검토 기록 내보내기' }).focus();
  await page.keyboard.press('Enter');
  const withoutNotesDownload = await withoutNotesPromise;
  const withoutNotes = await readFile((await withoutNotesDownload.path())!, 'utf8');
  expect(withoutNotes).not.toContain('private analyst note');
  expect(withoutNotes).toContain('검토 완료: 1');

  await page.getByLabel('보고서 메모 포함').focus();
  await page.keyboard.press('Space');
  await expect(page.getByText(/분석가 메모에는 내부 코드 정보나 민감정보가 포함될 수 있습니다/)).toBeVisible();

  page.once('dialog', (dialog) => dialog.dismiss());
  await page.getByRole('button', { name: '분석가 검토 기록 내보내기' }).click();
  await expect(page.getByRole('status').getByText('메모 포함을 확인하지 않아 다운로드를 취소했습니다.')).toBeVisible();
  expect(downloads).toBe(1);
  expect(scans).toBe(1);

  const downloadPromise = page.waitForEvent('download');
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: '분석가 검토 기록 내보내기' }).focus();
  await page.keyboard.press('Enter');
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('ai-code-security-analyst-review.md');
  const markdown = await readFile((await download.path())!, 'utf8');
  expect(markdown).toContain('private analyst note &#x3C;script&#x3E;');
  expect(markdown).not.toContain('<script>');
  expect(markdown).toContain('검토 대기: 1');
  expect(markdown).toContain('semgrep:0000000000000000bbbbbbbb');
  expect(markdown).not.toContain('synthetic-review-token');
  expect(scans).toBe(1);

  await page.evaluate(() => { URL.createObjectURL = () => { throw new Error('synthetic download failure'); }; });
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: '분석가 검토 기록 내보내기' }).click();
  await expect(page.getByText('보고서를 생성하거나 다운로드하지 못했습니다. 검사 결과와 브라우저 다운로드 설정을 확인하세요.')).toBeVisible();
  expect(downloads).toBe(2);
  expect(scans).toBe(1);

  const clearDialog = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  await page.getByRole('button', { name: '결과 지우기' }).click();
  await clearDialog;
  await expect(page.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeVisible();
  await expect(page.getByRole('button', { name: '분석가 검토 기록 내보내기' })).toHaveCount(0);
});
