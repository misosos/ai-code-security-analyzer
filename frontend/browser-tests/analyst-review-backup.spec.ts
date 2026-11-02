import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const findingId = 'semgrep:000000000000000000000001';
const finding = { finding_id: findingId, rule_id: 'baseline.rule-1', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/backup.ts', line_number: 8, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null };
const scan = { scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0, severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, issues: [], findings: [finding], limitations: ['finding_count_not_confirmed_vulnerability_count'] };
const backup = (status = 'reviewed', note?: string) => ({
  schema_version: 'analyst-review-backup/v1',
  scan_context: { target_id: 'project-a', rule_profile_id: 'baseline', experimental: false, semgrep_version: '1.182.1', scan_status: 'completed', received_at: '2026-10-31T12:00:00.000Z', finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0 },
  findings: [{ finding_id: findingId, rule_id: 'baseline.rule-1', file_path: 'src/backup.ts', line_number: 8, severity: 'high', finding_kind: 'pattern', review_status: status, ...(note === undefined ? {} : { note }) }],
});

test('분석가 JSON 백업은 명시적으로 만들고 검증 후 Finding 단위로만 적용한다', async ({ page }) => {
  let scans = 0; let scanCalls = 0;
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: { targets: [{ id: 'project-a', label: '합성 프로젝트' }], rule_profiles: [{ id: 'baseline', label: '기본 규칙', experimental: false }] } }));
  await page.route('**/api/v1/scans', (route) => { scanCalls++; scans++; return route.fulfill({ json: scan }); });
  await page.goto('/');
  await page.getByLabel('로컬 API 토큰').fill('synthetic-token-never-export');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  const panel = page.getByLabel('보고서와 검토 기록 내보내기');
  let downloadPromise = page.waitForEvent('download');
  await panel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('ai-code-security-analyst-review-backup.json');
  const exported = await readFile((await download.path())!, 'utf8');
  expect(JSON.parse(exported)).toMatchObject({ schema_version: 'analyst-review-backup/v1', findings: [{ review_status: 'pending' }] });
  expect(exported).not.toContain('synthetic-token-never-export');

  const input = page.getByLabel('검토 기록 불러오기(JSON)');
  await input.setInputFiles({ name: 'untrusted-backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backup('reviewed', '<img src=x onerror=alert(1)> imported note'))) });
  await expect(page.getByRole('status').filter({ hasText: '아직 어떤 기록도 적용되지 않았습니다' })).toBeVisible();
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('검토 대기');
  await expect(page.locator('img')).toHaveCount(0);
  await page.getByText('Finding별 기록 확인 (1)', { exact: true }).click();
  await page.screenshot({ path: '../docs/assets/phase8e/restore-preview-1440.png', fullPage: true });
  await page.getByLabel('검토 기록 복원 미리보기').getByRole('button', { name: '이 기록 적용' }).click();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
  await expect(page.getByLabel('분석가 메모')).toHaveValue('<img src=x onerror=alert(1)> imported note');
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('외부 백업에서 가져온 기록');
  expect(scanCalls).toBe(1);

  let downloads = 1;
  page.on('download', () => { downloads++; });
  await page.getByLabel('JSON 백업에 메모 포함').check();
  page.once('dialog', (dialog) => dialog.dismiss());
  await panel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
  await expect(page.getByRole('status').filter({ hasText: '백업을 취소했습니다' })).toBeVisible();
  expect(downloads).toBe(1);
  const noteDownloadPromise = page.waitForEvent('download');
  page.once('dialog', (dialog) => dialog.accept());
  await panel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
  const noteDownload = await noteDownloadPromise;
  const noteJson = await readFile((await noteDownload.path())!, 'utf8');
  expect(JSON.parse(noteJson).findings[0].note).toBe('<img src=x onerror=alert(1)> imported note');
  expect(noteJson).not.toContain('synthetic-token-never-export');
  expect(downloads).toBe(2);

  const confirm = page.waitForEvent('dialog').then((dialog) => dialog.dismiss());
  await input.setInputFiles({ name: 'overwrite.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backup('pending'))) });
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toBeVisible();
  await page.getByText('Finding별 기록 확인 (1)', { exact: true }).click();
  await page.getByLabel('검토 기록 복원 미리보기').getByRole('button', { name: '이 기록 적용' }).click();
  await confirm;
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
  expect(scanCalls).toBe(1);

  const mismatch = backup(); mismatch.scan_context.target_id = 'different-project';
  await input.setInputFiles({ name: 'mismatch.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(mismatch)) });
  await expect(page.getByRole('alert')).toContainText('검사 대상 ID가 다릅니다');
  await expect(page.getByLabel('검토 기록 복원 미리보기').getByRole('button', { name: '이 기록 적용' })).toHaveCount(0);

  const errorBackup = { ...backup(), extra: 'reject' };
  await input.setInputFiles({ name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(errorBackup)) });
  await expect(page.getByRole('status').filter({ hasText: '지원하지 않는 스키마' })).toBeVisible();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');

  await input.setInputFiles({ name: 'too-large.json', mimeType: 'application/json', buffer: Buffer.alloc(256 * 1024 + 1, 0x20) });
  await expect(page.getByRole('status').filter({ hasText: '파일이 256 KiB 제한을 초과합니다' })).toBeVisible();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');

  for (const width of [1920, 1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(dimensions.client);
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  await input.setInputFiles({ name: 'valid-again.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backup('reviewed'))) });
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: '검사 시작' }).click();
  const newScanConfirmation = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  await page.getByRole('button', { name: '검사 실행' }).click();
  await newScanConfirmation;
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toHaveCount(0);
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('pending');
  expect(scanCalls).toBe(2);
});
