import { expect, test } from '@playwright/test';
import { appendFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

test('D8 evidence gap scenario uses actual scan and server evaluation', async ({ page }) => {
  const mode = process.env.D8_GAP_CASE;
  test.skip(!mode, 'Run by isolated D8 scenario harness');
  if (!mode || !['same', 'comment', 'off'].includes(mode)) throw new Error('invalid_d8_scenario');
  const token = process.env.BROWSER_E2E_API_TOKEN;
  const target = process.env.BROWSER_E2E_INVESTIGATION_PATH;
  const rules = process.env.BROWSER_E2E_RULES_PATH;
  if (!token || !target || !rules) throw new Error('missing_synthetic_context');
  await page.goto('/');
  await expect(page.getByText(/API 연결됨/)).toBeVisible();
  await page.getByLabel('로컬 API 토큰').fill(token);
  await page.getByLabel('검사 대상').selectOption('synthetic-investigation');
  await page.getByLabel('검사 규칙 모음').selectOption('baseline');
  await page.getByText('소멸 근거 조사 선택').click();
  await page.getByLabel('소멸 근거 조사').check();
  if (mode !== 'off') await page.getByLabel('규칙 파일 동일성 증거 포함').check();
  const scanPath = mode === 'off' ? '/api/v2/investigation-scans' : '/api/v2/investigation-scans/rule-bytes';
  const firstResponse = page.waitForResponse((response) => new URL(response.url()).pathname === scanPath);
  await page.getByRole('button', { name: '검사 실행' }).click();
  const first = await (await firstResponse).json() as { scan: { findings: Array<{ finding_id: string; file_path: string }> } };
  expect(first.scan.findings.map((item) => item.file_path).sort()).toEqual(['retired.js', 'stable.js']);
  await page.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }).click();
  if (mode === 'comment') await appendFile(join(rules, 'security-baseline.yml'), '\n# D8 synthetic comment\n');
  else {
    await writeFile(join(target, 'retired.js'), 'function retired(input) { return String(input); }\n');
    await writeFile(join(target, 'added.js'), 'function added(input) { return eval(input); }\n');
  }
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 시작/ }).click();
  const secondResponse = page.waitForResponse((response) => new URL(response.url()).pathname === scanPath);
  await page.getByRole('button', { name: '검사 실행' }).click();
  const second = await (await secondResponse).json() as { scan: { findings: Array<{ finding_id: string; file_path: string }> } };
  if (mode === 'comment') expect(second.scan.findings.map((item) => item.finding_id).sort()).toEqual(first.scan.findings.map((item) => item.finding_id).sort());
  else expect(second.scan.findings.map((item) => item.file_path).sort()).toEqual(['added.js', 'stable.js']);
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await page.getByText('검사 결과 비교').click();
  const panel = page.getByRole('region', { name: '소멸 근거 조사' });
  await panel.getByRole('button', { name: '소멸 근거 조사 실행' }).click();
  const map = page.getByRole('region', { name: 'Security Evidence Gap Map' });
  await expect(map).toBeVisible();
  if (mode === 'same') {
    await expect(map).toContainText('선택된 단일 규칙 파일 사본의 바이트가 같습니다');
    await expect(map).toContainText('기준만 1건 · 양쪽 1건 · 현재만 1건');
  } else if (mode === 'comment') {
    await expect(map).toContainText('선택된 단일 규칙 파일 사본의 바이트가 다릅니다');
    await expect(map).toContainText('주석 변경도 차이를 만듭니다');
  } else await expect(map).toContainText('규칙 바이트 비교를 요청하지 않았습니다');
  await expect(map).toContainText('소스 스냅샷을 수집하지 않았습니다');
  await expect(map).toContainText('전체 로딩 규칙 동일성은 검증되지 않았습니다');
  await expect(map).toContainText('전체 검사 범위의 완전성은 검증되지 않았습니다');
  await expect(map).toContainText('취약점 해결 여부는 이 조사만으로 판정할 수 없습니다');
  await expect(map).not.toContainText(token);
  await panel.getByRole('button', { name: '조사 증거 해제' }).click();
  await expect(map).toHaveCount(0);
});
