import { expect, test } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const output = resolve(process.cwd(), '../.taste-skill/after');

test('captures large-type workspace at desktop sizes and audits rendered text', async ({ page }) => {
  await mkdir(output, { recursive: true });
  await page.route('**/api/v1/health', (route) => route.fulfill({ json: { status: 'ok', service: 'ai-code-security-analyzer' } }));
  await page.route('**/api/v1/options', (route) => route.fulfill({ json: {
    targets: [{ id: 'synthetic-project', label: '합성 검토 프로젝트' }],
    rule_profiles: [{ id: 'baseline', label: '기본 보안 규칙', experimental: false }],
  } }));
  await page.route('**/api/v1/scans', (route) => route.fulfill({ json: {
    scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: 2,
    displayed_finding_count: 2, omitted_finding_count: 0,
    severity_counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
    issues: [], limitations: ['scan_result_is_not_safety_proof'],
    findings: [
      { finding_id: 'semgrep:0123456789abcdef01234567', rule_id: 'synthetic.eval-example', severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'src/routes/example.js', line_number: 12, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }], validation_error_code: null },
      { finding_id: 'semgrep:1123456789abcdef01234567', rule_id: 'synthetic.taint-example', severity: 'medium', verification_status: 'unverified', finding_kind: 'taint', file_path: 'src/controllers/example.js', line_number: 24, evidence_validation_status: 'validated', supported_claims: ['taint_rule_match_reported'], restricted_claims: [{ claim_type: 'flow_trace_available', decision: 'unavailable', reason_codes: ['flow_trace_absent'] }], validation_error_code: null },
    ],
  } }));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '코드 보안 검사' })).toBeVisible();

  for (const viewport of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(viewport);
    const measurements = await page.evaluate(() => {
      const selectors = [
        'body', '.brand-emblem', '.sidebar-status-copy strong', '.sidebar-status-copy small', '.nav-item',
        '.workspace-title h1', '.workspace-title > p', '.control-label', '.mission-control small',
        '.mission-control select', '.token-input-control input', '.run-button',
        '.launch-brief-copy h2', '.launch-brief-copy p', '.launch-steps li',
      ];
      return {
        viewport: { width: innerWidth, height: innerHeight },
        documentWidth: document.documentElement.scrollWidth,
        samples: selectors.map((selector) => {
          const element = document.querySelector(selector);
          if (!element) return { selector, missing: true };
          const style = getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          return { selector, fontSize: parseFloat(style.fontSize), lineHeight: style.lineHeight, box: { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) } };
        }),
      };
    });
    expect(measurements.documentWidth).toBeLessThanOrEqual(viewport.width);
    expect(measurements.samples.filter((sample) => 'missing' in sample)).toEqual([]);
    const sizes = Object.fromEntries(measurements.samples.map((sample) => ['selector' in sample ? sample.selector : '', 'fontSize' in sample ? sample.fontSize : 0]));
    expect(sizes['body']).toBeGreaterThanOrEqual(20);
    expect(sizes['.nav-item']).toBeGreaterThanOrEqual(18);
    expect(sizes['.workspace-title h1']).toBeGreaterThanOrEqual(36);
    expect(sizes['.workspace-title > p']).toBeGreaterThanOrEqual(18);
    expect(sizes['.mission-control select']).toBeGreaterThanOrEqual(18);
    expect(sizes['.run-button']).toBeGreaterThanOrEqual(18);
    await page.screenshot({ path: resolve(output, `start-${viewport.width}x${viewport.height}.png`), animations: 'disabled' });
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByLabel('로컬 API 토큰').fill('synthetic-visual-only-token');
  await page.getByRole('button', { name: '검사 실행' }).click();
  await expect(page.getByRole('heading', { name: '정상 완료' })).toBeVisible();
  await expect(page.getByLabel('Finding 목록').getByRole('button')).toHaveCount(2);
  await page.screenshot({ path: resolve(output, 'results-1440x900.png'), animations: 'disabled' });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({ path: resolve(output, 'results-1920x1080.png'), animations: 'disabled' });

  const undersizedText = await page.evaluate(() => {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const undersized: string[] = [];
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const text = node.textContent?.trim() ?? '';
      const parent = node.parentElement;
      if (!text || !parent || parent.closest('.sr-only,[aria-hidden="true"]') || parent.tagName === 'OPTION') continue;
      const style = getComputedStyle(parent);
      if (style.display === 'none' || style.visibility === 'hidden' || !parent.getClientRects().length) continue;
      if (parseFloat(style.fontSize) < 17) undersized.push(`${parent.tagName.toLowerCase()}.${String(parent.className)} "${text.slice(0, 70)}": ${style.fontSize}`);
    }
    return undersized;
  });
  expect(undersizedText).toEqual([]);
});
