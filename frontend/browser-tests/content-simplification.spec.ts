import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const output = resolve(process.cwd(), '../docs/assets/ui-d4b/after');
const finding = {
  finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high',
  verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/routes/review.js', line_number: 12,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null,
};
const completed = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 1,
  displayed_finding_count: 1, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  issues: [], limitations: ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'], findings: [finding],
};

test('UI-D4B 간소화한 콘텐츠의 화면 상태와 세션별 검토 흐름', async ({ page }) => {
  await mkdir(output, { recursive: true });
  let response: Record<string, unknown> = completed;
  let apiOffline = false;
  let requestFails = false;
  await page.route('**/api/v1/health', (route) => apiOffline ? route.abort() : route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => apiOffline ? route.abort() : route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: '합성 검수 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: '기본 보안 규칙', experimental: false }, { id: 'experimental', label: '실험 규칙', experimental: true }],
  } }));
  await page.route('**/api/v1/scans', (route) => requestFails ? route.fulfill({ status: 503, json: { error: 'synthetic_failure' } }) : route.fulfill({ json: response }));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();
  await expect(page.getByText('API 연결됨')).toBeVisible();
  await expect(page.getByText('옵션 불러옴')).toHaveCount(0);
  await expect(page.getByText('등록된 프로젝트와 규칙을 선택해 검사합니다.')).toBeVisible();
  await expect(page.getByRole('heading', { name: '탐지 결과는 검토 후보입니다.' })).toBeVisible();
  await expect(page.getByText('검사 흐름', { exact: true })).toHaveCount(0);
  const token = page.getByLabel('로컬 API 토큰');
  await token.fill('synthetic-only-token');
  await expect(token).toHaveAttribute('type', 'password');
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  await page.screenshot({ path: resolve(output, 'start-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({ path: resolve(output, 'start-1920x1080.png'), animations: 'disabled' });

  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await expect(page.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeVisible();
  await expect(page.getByText('현재 브라우저 세션의 결과만 표시합니다.')).toBeVisible();
  await page.screenshot({ path: resolve(output, 'empty-results-1440x900.png'), animations: 'disabled' });
  await page.getByRole('button', { name: '검사 시작' }).last().click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '발견 항목' })).toContainText('1');
  await page.screenshot({ path: resolve(output, 'finding-results-1440x900.png'), animations: 'disabled' });
  await page.screenshot({ path: resolve(output, 'finding-detail-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(output, 'finding-results-390x844.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByLabel('파일 경로, 규칙 이름 또는 ID 검색').fill('no-match');
  await expect(page.getByLabel('Finding 목록')).toContainText('검색 또는 필터와 일치하는 결과가 없습니다.');
  await page.screenshot({ path: resolve(output, 'filtered-empty-1440x900.png'), animations: 'disabled' });

  response = { ...completed, finding_count: 0, displayed_finding_count: 0, severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [] };
  await page.getByRole('button', { name: '검사 시작' }).first().click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await expect(page.getByText('이번 검사에서 후보가 나오지 않았습니다. 검사되지 않은 문제까지 안전하다는 뜻은 아닙니다.')).toBeVisible();
  await page.screenshot({ path: resolve(output, 'zero-findings-1440x900.png'), animations: 'disabled' });

  response = { ...completed, scan_status: 'partial', completed: false, limitations: ['scan_partial'], issues: [] };
  await page.getByRole('button', { name: '검사 시작' }).first().click();
  await page.getByRole('button', { name: '검사 실행' }).click();
  await page.getByRole('navigation', { name: '화면 이동' }).getByRole('button', { name: /검사 결과/ }).click();
  await expect(page.getByText('부분 검사입니다. 일부 파일이나 규칙의 결과가 빠졌을 수 있습니다.')).toBeVisible();
  await page.screenshot({ path: resolve(output, 'partial-results-1440x900.png'), animations: 'disabled' });

  await page.getByRole('button', { name: '사용 안내' }).click();
  await expect(page.getByRole('heading', { name: '사용 방법' })).toBeVisible();
  const admin = page.locator('.advanced-setup > summary');
  await expect(admin.locator('xpath=..')).not.toHaveAttribute('open');
  await page.screenshot({ path: resolve(output, 'guide-basic-1440x900.png'), animations: 'disabled' });
  await admin.click();
  await expect(page.getByText(/AI_CODE_SECURITY_TARGETS/)).toBeVisible();
  await page.screenshot({ path: resolve(output, 'guide-admin-expanded-1440x900.png'), animations: 'disabled' });
  const expert = page.getByRole('region', { name: '보안 분석 용어 도움말' }).locator('details > summary');
  await expect(expert.locator('xpath=..')).not.toHaveAttribute('open');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: resolve(output, 'guide-mobile-390x844.png'), animations: 'disabled' });
  await page.getByRole('button', { name: '내비게이션 열기' }).click();
  await expect(page.getByRole('dialog', { name: '주 메뉴' })).toBeVisible();
  await page.screenshot({ path: resolve(output, 'mobile-start-390x844.png'), animations: 'disabled' });
  await page.getByRole('dialog', { name: '주 메뉴' }).getByRole('button', { name: '검사 시작' }).click();

  apiOffline = true;
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('검사 서버를 실행하고');
  await page.screenshot({ path: resolve(output, 'api-error-1440x900.png'), animations: 'disabled' });
  apiOffline = false;
  await page.getByRole('button', { name: '다시 연결' }).click();
  await expect(page.getByText('API 연결됨')).toBeVisible();

  requestFails = true;
  await page.getByLabel('로컬 API 토큰').fill('synthetic-only-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('alert')).toContainText('요청이 거부되었습니다');
  await page.screenshot({ path: resolve(output, 'request-error-1440x900.png'), animations: 'disabled' });

  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1440, height: 900 }, { width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `가로 넘침 ${viewport.width}x${viewport.height}`).toBeLessThanOrEqual(0);
  }
});
