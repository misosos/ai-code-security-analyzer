import { expect, test } from '@playwright/test';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, sep } from 'node:path';

const canary = 'SYNTHETIC_BROWSER_CANARY_MUST_NOT_LEAK';
const memoA = '합성 테스트용 수동 검토 기록 - 추가 확인 필요';
const memoB = '합성 B 검토 메모';
const memoC = '합성 C 복원 메모';

type Finding = {
  finding_id: string;
  rule_id: string;
  severity: string;
  verification_status: string;
  finding_kind: string;
  file_path: string | null;
  line_number: number | null;
  evidence_validation_status: string;
  supported_claims: string[];
  restricted_claims: Array<{ claim_type: string; decision: string }>;
};
type Scan = {
  scan_status: string;
  completed: boolean;
  semgrep_version: string;
  finding_count: number;
  displayed_finding_count: number;
  omitted_finding_count: number;
  findings: Finding[];
};

async function downloadText(page: import('@playwright/test').Page, button: import('@playwright/test').Locator, filename: string) {
  const promise = page.waitForEvent('download');
  await button.click();
  const download = await promise;
  expect(download.suggestedFilename()).toBe(filename);
  return readFile((await download.path())!, 'utf8');
}

test('실제 FastAPI·Semgrep에서 분석가 검토·백업·비교 전체 업무 흐름을 검증한다', async ({ page }) => {
  test.setTimeout(360_000);
  const token = process.env.BROWSER_E2E_API_TOKEN;
  const apiOrigin = process.env.BROWSER_E2E_BASE_URL;
  const privatePath = process.env.BROWSER_E2E_PRIVATE_PATH;
  const rawWorkflowPath = process.env.BROWSER_E2E_WORKFLOW_PATH;
  if (!token || !apiOrigin || !privatePath || !rawWorkflowPath) throw new Error('real_analyst_workflow_configuration_required');

  const safePrivateRoot = await realpath(privatePath);
  const workflowPath = await realpath(rawWorkflowPath);
  const pathFromRoot = relative(safePrivateRoot, workflowPath);
  if (!pathFromRoot || pathFromRoot.startsWith(`..${sep}`) || pathFromRoot === '..' || isAbsolute(pathFromRoot)) {
    throw new Error('real_analyst_workflow_fixture_path_invalid');
  }
  const backupDirectory = dirname(workflowPath);
  const scanRequests: Array<{ method: string; target: string | undefined; auth: string }> = [];
  const externalRequests: string[] = [];
  const scanResponses: Scan[] = [];
  let downloadEvents = 0;
  page.on('download', () => { downloadEvents += 1; });
  page.on('request', (request) => {
    if (!request.url().startsWith(apiOrigin)) externalRequests.push(new URL(request.url()).origin);
    if (request.url().endsWith('/api/v1/scans')) {
      const headers = request.headers();
      scanRequests.push({
        method: request.method(),
        target: request.postDataJSON()?.target_id as string | undefined,
        auth: headers['x-local-api-token'] === token && !request.url().includes(token) ? 'header-only' : 'invalid',
      });
    }
  });
  page.on('response', async (response) => {
    if (response.url().endsWith('/api/v1/scans') && response.status() === 200) {
      scanResponses.push(await response.json() as Scan);
    }
  });

  const optionsPromise = page.waitForResponse((response) => response.url().endsWith('/api/v1/options'));
  const document = await page.goto('/');
  expect(document?.status()).toBe(200);
  await expect(page.getByText('API 연결됨')).toBeVisible();
  const optionsBody = await (await optionsPromise).text();
  expect(optionsBody).toContain('synthetic-workflow');
  expect(optionsBody).not.toContain(safePrivateRoot);
  await expect(page.getByRole('option', { name: 'Synthetic Workflow', exact: true })).toBeAttached();
  await expect(page.getByRole('option', { name: 'Baseline Rules', exact: true })).toBeAttached();
  await page.getByLabel('로컬 API 토큰').fill(token);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.getByLabel('검사 대상').selectOption('synthetic-workflow');
  await page.getByLabel('검사 규칙 모음').selectOption('baseline');

  const firstResponsePromise = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans'));
  await page.getByRole('button', { name: '검사 실행' }).click();
  const firstResponse = await firstResponsePromise;
  expect(firstResponse.status()).toBe(200);
  const firstBody = await firstResponse.text();
  expect(firstBody).not.toContain(safePrivateRoot);
  expect(firstBody).not.toContain(token);
  expect(firstBody).not.toContain(canary);
  const first = JSON.parse(firstBody) as Scan;
  expect(first.scan_status).toBe('completed');
  expect(first.completed).toBe(true);
  expect(first.semgrep_version).toBe('1.182.1');
  expect(first.omitted_finding_count).toBe(0);
  expect(first.finding_count).toBe(2);
  expect(first.displayed_finding_count).toBe(2);
  const stableA = first.findings.find((finding) => finding.file_path === 'stable.js');
  const retiredB = first.findings.find((finding) => finding.file_path === 'retired.js');
  expect(stableA).toBeDefined();
  expect(retiredB).toBeDefined();
  for (const finding of [stableA!, retiredB!]) {
    expect(finding.finding_id).toMatch(/^semgrep:[a-f0-9]{24}$/);
    expect(finding.rule_id).toBe('baseline.javascript-dynamic-eval');
    expect(finding.verification_status).toBe('unverified');
    expect(['validated', 'unverified']).toContain(finding.evidence_validation_status);
  }
  expect(stableA!.finding_id).not.toBe(retiredB!.finding_id);
  console.log(`phase8f-baseline-findings stable=${stableA!.finding_id} retired=${retiredB!.finding_id}`);
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(token);
  await expect(page.locator('body')).not.toContainText(safePrivateRoot);
  await expect(page.getByRole('button', { name: '비교 기준으로 지정' })).toBeVisible();
  await expect(page.getByRole('button', { name: '비교 보고서 내보내기' })).toHaveCount(0);

  await page.getByRole('button', { name: '비교 기준으로 지정' }).click();
  await expect(page.getByRole('status').filter({ hasText: '현재 검사 결과를 비교 기준으로 지정했습니다' })).toBeVisible();
  await expect(page.getByText('Semgrep 1.182.1').first()).toBeVisible();

  const findingsList = page.getByRole('region', { name: 'Finding 목록' });
  const selectFinding = async (finding: Finding) => {
    await findingsList.getByRole('button', { name: new RegExp(finding.file_path!.replace('.', '\\.') + `:${finding.line_number}`) }).click();
    await expect(page.getByLabel('선택한 Finding 상세')).toBeVisible();
  };
  await selectFinding(stableA!);
  await page.getByLabel('수동 검토 상태').selectOption('needs_followup');
  await page.getByLabel('분석가 메모').fill(memoA);
  await page.getByText('기술 근거와 제한 자세히 보기').click();
  const stableTechnicalBefore = await page.getByLabel('선택한 Finding 상세').innerText();
  expect(stableTechnicalBefore).toContain('미검증');
  expect(stableTechnicalBefore).toContain(stableA!.evidence_validation_status);
  await selectFinding(retiredB!);
  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await page.getByLabel('분석가 메모').fill(memoB);
  expect(await page.getByLabel('수동 검토 상태').inputValue()).toBe('reviewed');
  expect(scanRequests).toHaveLength(1);

  const currentMarkdown = await downloadText(page, page.getByRole('button', { name: '현재 검사 결과 내보내기' }), 'ai-code-security-ui-review-summary.md');
  expect(currentMarkdown).toContain(stableA!.finding_id);
  expect(currentMarkdown).not.toContain(memoA);
  expect(currentMarkdown).not.toContain(memoB);
  expect(currentMarkdown).not.toContain(token);
  expect(currentMarkdown).not.toContain(safePrivateRoot);
  expect(currentMarkdown).not.toContain(canary);

  await page.getByText('분석가 검토 기록 내보내기', { exact: true }).click();
  const analystPanel = page.getByLabel('보고서와 검토 기록 내보내기');
  const analystMarkdown = await downloadText(page, analystPanel.getByRole('button', { name: '분석가 검토 기록 내보내기 · Markdown 다운로드' }), 'ai-code-security-analyst-review.md');
  expect(analystMarkdown).toContain('추가 확인 필요: 1');
  expect(analystMarkdown).toContain('검토 완료: 1');
  expect(analystMarkdown).not.toContain(memoA);
  expect(analystMarkdown).not.toContain(memoB);
  expect(analystMarkdown).not.toContain(token);
  expect(analystMarkdown).not.toContain(safePrivateRoot);
  expect(analystMarkdown).not.toContain(canary);

  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  const backupPanel = page.getByLabel('보고서와 검토 기록 내보내기');
  const initialBackup = await downloadText(page, backupPanel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }), 'ai-code-security-analyst-review-backup.json');
  expect(initialBackup).not.toContain(memoA);
  expect(initialBackup).not.toContain(memoB);
  expect(initialBackup).not.toContain(token);
  expect(initialBackup).not.toContain(safePrivateRoot);
  expect(initialBackup).not.toContain(canary);
  const initialBackupJson = JSON.parse(initialBackup) as { findings: Array<{ finding_id: string; review_status: string; note?: string }> };
  expect(initialBackupJson.findings).toHaveLength(2);
  expect(initialBackupJson.findings.find((item) => item.finding_id === stableA!.finding_id)?.review_status).toBe('needs_followup');
  expect(initialBackupJson.findings.find((item) => item.finding_id === retiredB!.finding_id)?.review_status).toBe('reviewed');
  expect(downloadEvents).toBe(3);
  const initialBackupPath = join(backupDirectory, 'workflow-baseline-review-backup.json');
  // Keep the downloaded fixture only in the runner-owned temporary directory for restore checks.
  await writeFile(initialBackupPath, initialBackup, { mode: 0o600 });

  await backupPanel.getByLabel('JSON 백업에 메모 포함').check();
  page.once('dialog', (dialog) => dialog.dismiss());
  await backupPanel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
  await expect(page.getByRole('status').filter({ hasText: '메모 포함을 확인하지 않아' })).toBeVisible();
  expect(downloadEvents).toBe(3);
  const noteBackup = await (async () => {
    const pendingDownload = page.waitForEvent('download');
    page.once('dialog', (dialog) => dialog.accept());
    await backupPanel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
    const download = await pendingDownload;
    expect(download.suggestedFilename()).toBe('ai-code-security-analyst-review-backup.json');
    expect(downloadEvents).toBe(4);
    return readFile((await download.path())!, 'utf8');
  })();
  expect(noteBackup).toContain(memoA);
  expect(noteBackup).toContain(memoB);
  expect(noteBackup).not.toContain(token);
  expect(noteBackup).not.toContain(safePrivateRoot);
  expect(noteBackup).not.toContain(canary);
  const initialBackupWithNotesPath = join(backupDirectory, 'workflow-baseline-review-backup-with-notes.json');
  await writeFile(initialBackupWithNotesPath, noteBackup, { mode: 0o600 });
  expect(scanRequests).toHaveLength(1);

  // Modify only this test runner's owned synthetic project after scan 1 has completed.
  await writeFile(join(workflowPath, 'retired.js'), [
    'function retired(input) {',
    '  return input;',
    '}',
    '',
  ].join('\n'), { mode: 0o600 });
  await writeFile(join(workflowPath, 'added.js'), [
    'function added(input) {',
    '  return new Function(input)();',
    '}',
    '',
  ].join('\n'), { mode: 0o600 });

  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  const cancelFirst = page.waitForEvent('dialog').then((dialog) => dialog.dismiss());
  await page.getByRole('button', { name: '검사 실행' }).click();
  await cancelFirst;
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
  expect(scanRequests).toHaveLength(1);

  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  const confirmSecond = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  const secondResponsePromise = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans'));
  await page.getByRole('button', { name: '검사 실행' }).click();
  await confirmSecond;
  const secondResponse = await secondResponsePromise;
  expect(secondResponse.status()).toBe(200);
  const secondBody = await secondResponse.text();
  expect(secondBody).not.toContain(safePrivateRoot);
  expect(secondBody).not.toContain(token);
  expect(secondBody).not.toContain(canary);
  const second = JSON.parse(secondBody) as Scan;
  expect(second.scan_status).toBe('completed');
  expect(second.completed).toBe(true);
  expect(second.semgrep_version).toBe(first.semgrep_version);
  expect(second.omitted_finding_count).toBe(0);
  expect(second.finding_count).toBe(2);
  const stableA2 = second.findings.find((finding) => finding.file_path === 'stable.js');
  const addedC = second.findings.find((finding) => finding.file_path === 'added.js');
  expect(stableA2?.finding_id).toBe(stableA!.finding_id);
  expect(stableA2).toEqual(stableA);
  expect(second.findings.some((finding) => finding.file_path === 'retired.js')).toBe(false);
  expect(addedC).toBeDefined();
  expect(addedC?.finding_id).toMatch(/^semgrep:[a-f0-9]{24}$/);
  expect(addedC?.finding_id).not.toBe(stableA!.finding_id);
  console.log(`phase8f-current-findings stable=${stableA2!.finding_id} added=${addedC!.finding_id}`);
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toHaveCount(0);
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('검토 대기');
  expect(scanRequests).toHaveLength(2);

  await page.getByText('검사 결과 비교').click();
  const categories = page.getByLabel('Finding 관찰 차이');
  await expect(categories).toContainText('이번 검사에서만 관찰');
  await expect(categories).toContainText('양쪽에서 관찰');
  await expect(categories).toContainText('기준 검사에서만 관찰');
  await expect(categories).toContainText('1');
  await page.getByRole('group', { name: '비교 항목 범주' }).getByRole('button', { name: /이번 검사에서만 관찰/ }).click();
  await expect(page.getByRole('region', { name: '이번 검사에서만 관찰 목록' })).toContainText('added.js');
  await page.getByRole('group', { name: '비교 항목 범주' }).getByRole('button', { name: /양쪽에서 관찰/ }).click();
  await expect(page.getByRole('region', { name: '양쪽에서 관찰 목록' })).toContainText('stable.js');
  await page.getByRole('group', { name: '비교 항목 범주' }).getByRole('button', { name: /기준 검사에서만 관찰/ }).click();
  await expect(page.getByRole('region', { name: '기준 검사에서만 관찰 목록' })).toContainText('retired.js');

  const comparisonMarkdown = await downloadText(page, page.getByRole('button', { name: '비교 보고서 내보내기' }), 'ai-code-security-comparison.md');
  for (const value of ['이번 검사에서만 관찰: 1', '양쪽에서 관찰: 1', '기준 검사에서만 관찰: 1', stableA!.finding_id, retiredB!.finding_id, addedC!.finding_id, 'Semgrep 버전: 1.182.1', '취약점의 발생·해결']) {
    expect(comparisonMarkdown).toContain(value);
  }
  expect(comparisonMarkdown).not.toContain(memoA);
  expect(comparisonMarkdown).not.toContain(memoB);
  expect(comparisonMarkdown).not.toContain(token);
  expect(comparisonMarkdown).not.toContain(safePrivateRoot);
  expect(comparisonMarkdown).not.toContain(canary);
  expect(scanRequests).toHaveLength(2);
  expect(downloadEvents).toBe(5);

  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  const input = page.getByLabel('검토 기록 불러오기(JSON)');
  await input.setInputFiles(initialBackupPath);
  await expect(page.getByLabel('검토 기록 복원 미리보기').getByRole('alert')).toContainText('Finding ID 구성이 다릅니다.');
  await expect(page.getByLabel('검토 기록 복원 미리보기').getByRole('button', { name: '이 기록 적용' })).toHaveCount(0);
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('검토 대기');
  await expect(page.getByLabel('분석가 메모')).toHaveValue('');
  expect(scanRequests).toHaveLength(2);

  await selectFinding(stableA2!);
  await page.getByLabel('수동 검토 상태').selectOption('needs_followup');
  await page.getByLabel('분석가 메모').fill(memoA);
  await selectFinding(addedC!);
  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await page.getByLabel('분석가 메모').fill(memoC);
  await page.getByLabel('JSON 백업에 메모 포함').check();
  const currentNoteBackupPromise = page.waitForEvent('download');
  page.once('dialog', (dialog) => dialog.accept());
  await backupPanel.getByRole('button', { name: '검토 기록 백업 JSON 다운로드' }).click();
  const currentBackupDownload = await currentNoteBackupPromise;
  expect(currentBackupDownload.suggestedFilename()).toBe('ai-code-security-analyst-review-backup.json');
  expect(downloadEvents).toBe(6);
  const currentBackupText = await readFile((await currentBackupDownload.path())!, 'utf8');
  const currentBackupPath = join(backupDirectory, 'workflow-current-review-backup.json');
  await writeFile(currentBackupPath, currentBackupText, { mode: 0o600 });
  expect(currentBackupText).toContain(memoA);
  expect(currentBackupText).toContain(memoC);
  expect(currentBackupText).not.toContain(token);
  expect(currentBackupText).not.toContain(safePrivateRoot);
  expect(currentBackupText).not.toContain(canary);

  // Re-scan the identical synthetic tree to establish a fresh but metadata-identical current context.
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  const confirmThird = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  const thirdResponsePromise = page.waitForResponse((response) => response.url().endsWith('/api/v1/scans'));
  await page.getByRole('button', { name: '검사 실행' }).click();
  await confirmThird;
  const thirdResponse = await thirdResponsePromise;
  expect(thirdResponse.status()).toBe(200);
  const third = JSON.parse(await thirdResponse.text()) as Scan;
  expect(third.scan_status).toBe('completed');
  expect(third.finding_count).toBe(2);
  expect(third.omitted_finding_count).toBe(0);
  expect(third.findings.map((finding) => finding.finding_id).sort()).toEqual(second.findings.map((finding) => finding.finding_id).sort());
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toHaveCount(0);
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('검토 대기');
  expect(scanRequests).toHaveLength(3);

  await page.getByText('검토 기록 백업 및 복원', { exact: true }).click();
  const currentFindings = third.findings;
  const stableA3 = currentFindings.find((finding) => finding.file_path === 'stable.js')!;
  const addedC3 = currentFindings.find((finding) => finding.file_path === 'added.js')!;
  await selectFinding(stableA3);
  await page.getByLabel('수동 검토 상태').selectOption('reviewed');
  await page.getByLabel('분석가 메모').fill('현재 기록 덮어쓰기 확인용');
  await input.setInputFiles(currentBackupPath);
  await expect(page.getByText('아직 어떤 기록도 적용되지 않았습니다.')).toBeVisible();
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
  await expect(page.getByLabel('분석가 메모')).toHaveValue('현재 기록 덮어쓰기 확인용');
  await page.getByText(/Finding별 기록 확인/).click();
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toContainText(memoA);
  await expect(page.getByLabel('검토 기록 복원 미리보기')).toContainText('백업: 추가 확인 필요 · 현재: 검토 완료');
  const restorePanel = page.getByLabel('검토 기록 복원 미리보기');
  const stablePreview = restorePanel.locator('li').filter({ hasText: stableA3.file_path! });
  const applyButton = stablePreview.getByRole('button', { name: '이 기록 적용' });
  const cancelOverwrite = page.waitForEvent('dialog').then((dialog) => dialog.dismiss());
  await applyButton.click();
  await cancelOverwrite;
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('reviewed');
  await expect(page.getByLabel('분석가 메모')).toHaveValue('현재 기록 덮어쓰기 확인용');
  const acceptOverwrite = page.waitForEvent('dialog').then((dialog) => dialog.accept());
  await applyButton.click();
  await acceptOverwrite;
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('needs_followup');
  await expect(page.getByLabel('분석가 메모')).toHaveValue(memoA);
  await expect(page.getByLabel('선택한 Finding 상세')).toContainText('외부 백업에서 가져온 기록');

  await selectFinding(addedC3);
  await expect(page.getByLabel('수동 검토 상태')).toHaveValue('pending');
  await expect(page.getByLabel('분석가 메모')).toHaveValue('');
  expect(scanRequests.map((request) => request.target)).toEqual(['synthetic-workflow', 'synthetic-workflow', 'synthetic-workflow']);
  expect(scanRequests.map((request) => request.auth)).toEqual(['header-only', 'header-only', 'header-only']);
  expect(externalRequests).toEqual([]);
  expect(scanResponses).toHaveLength(3);
  for (const response of scanResponses) {
    expect(response.finding_count).toBe(response.displayed_finding_count);
    expect(response.omitted_finding_count).toBe(0);
    expect(response.findings.every((finding) => finding.verification_status === 'unverified')).toBe(true);
  }
  await expect(page.locator('body')).not.toContainText(token);
  await expect(page.locator('body')).not.toContainText(safePrivateRoot);
  await expect(page.locator('body')).not.toContainText(canary);
  expect(scanRequests).toHaveLength(3);

  for (const [width, height] of [[1920,1080],[1440,900],[1024,768],[768,1024],[390,844],[320,800]]) {
    await page.setViewportSize({ width, height });
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(dimensions.client);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  const screenshots = join(process.cwd(), '../docs/assets/phase8f');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(screenshots, { recursive: true });
  await page.screenshot({ path: join(screenshots, 'workflow-review-1440.png'), fullPage: true });
});
