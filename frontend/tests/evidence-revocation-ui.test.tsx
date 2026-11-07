import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../src/app/App';

const finding = {
  finding_id: `semgrep:${'a'.repeat(24)}`, rule_id: 'baseline.javascript-dynamic-eval',
  severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: 'sample.js', line_number: 1,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null,
};
const response = (partial: boolean) => ({
  scan_status: partial ? 'partial' : 'completed', completed: !partial, semgrep_version: '1.182.1',
  finding_count: 1, displayed_finding_count: 1, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  findings: [finding], issues: partial ? ['evidence_unavailable'] : [], limitations: ['scan_result_is_not_safety_proof', ...(partial ? ['scan_partial'] : [])],
});
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
let release: (init: RequestInit) => Promise<Response>;
let scans = 0;
function install(partial = true) {
  vi.mocked(fetch).mockImplementation(async (input, init) => {
    const url = String(input);
    if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
    if (url.endsWith('/options')) return json({ targets: [{ id: 'local-project', label: 'Synthetic' }], rule_profiles: [{ id: 'baseline', label: 'Baseline', experimental: false }] });
    if (url.endsWith('/investigation-scans')) return json({ contract_version: 'investigation-scan/v1', run_handle: (++scans === 1 ? 'A' : 'B').repeat(43), scan: response(partial) });
    if (url.endsWith('/investigation-release')) return release(init!);
    if (url.endsWith('/investigations')) return json({ contract_version: 'investigation-session/v1', investigation_handle: 'S'.repeat(43) }, 201);
    if (url.endsWith('/investigations/evaluate')) return json({
      contract_version: 'finding-disappearance-evaluation/v1', comparability: 'COMPARABLE', overall_assessment: 'UNDETERMINED',
      findings: [{ finding_id: finding.finding_id, category: 'shared', path_observation: null, skip_hypothesis: null, source_snapshot_hypothesis: null, rule_identity_hypothesis: null }],
      limitation_codes: ['source_snapshot_not_collected', 'loaded_rule_identity_unverified', 'scope_completeness_unverified', 'rule_bytes_unverified'],
    });
    throw new Error('unexpected_test_request');
  });
}
async function start(partial = true) {
  install(partial);
  const user = userEvent.setup(); render(<App/>);
  await screen.findByText('API 연결됨');
  await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-followup-token');
  await user.click(screen.getByText('소멸 근거 조사 선택'));
  await user.click(screen.getByLabelText('소멸 근거 조사'));
  await user.click(screen.getByRole('button', { name: '검사 실행' }));
  await screen.findByText('현재 응답에 서버 조사 증거가 연결됐습니다.');
  return user;
}
beforeEach(() => { scans = 0; vi.stubGlobal('fetch', vi.fn()); release = async () => new Response(null, { status: 204 }); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('부분 기준 저장은 정상 비교를 약속하지 않고 기준 해제 후에도 Finding을 유지한다', async () => {
  const user = await start();
  await user.click(screen.getByRole('button', { name: '부분 조사 결과를 증거 기준으로 저장' }));
  const comparison = screen.getByRole('region', { name: '검사 결과 비교' });
  expect(within(comparison).getByText(/부분 검사 기준을 저장했습니다/)).toHaveTextContent('정상 결과 비교는 불가');
  expect(within(comparison).queryByText(/새 검사를 실행하면 결과 차이를 확인/)).not.toBeInTheDocument();
  await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 시작/ }));
  await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 결과/ }));
  expect(screen.getByText(/부분 검사 기준을 저장했습니다/)).toHaveTextContent('정상 결과 비교는 불가');
  await user.click(screen.getByRole('button', { name: '비교 기준 해제' }));
  expect(within(screen.getByRole('region', { name: '검사 결과 비교' })).getByText(/비교 기준이 없습니다/)).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: '검사 결과' })).toBeInTheDocument();
});

it('정상 완료 기준의 새 검사 안내를 유지한다', async () => {
  const user = await start(false);
  expect(screen.getByText('비교 기준 없음')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }));
  expect(screen.getByText(/같은 대상과 규칙으로 새 검사를 실행하면 결과 차이/)).toBeInTheDocument();
});

it.each(['network', 'server', 'timeout'] as const)('해제 %s 실패에서 서버 성공을 주장하지 않고 로컬 증거 재사용을 차단한다', async (failure) => {
  const user = await start();
  const controller = new AbortController();
  if (failure === 'timeout') vi.spyOn(AbortSignal, 'timeout').mockReturnValue(controller.signal);
  release = async (init) => {
    if (failure === 'server') return json({ error: 'internal_unavailable' }, 503);
    if (failure === 'network') throw new TypeError('synthetic_network_failure');
    return new Promise((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('timeout', 'AbortError'))));
  };
  await user.click(screen.getByRole('button', { name: '조사 증거 해제' }));
  if (failure === 'timeout') { expect(AbortSignal.timeout).toHaveBeenCalledWith(5000); controller.abort(); }
  const panel = screen.getByRole('region', { name: '소멸 근거 조사' });
  expect(await within(panel).findByRole('alert')).toHaveTextContent('서버 증거 해제를 확인하지 못했습니다');
  expect(within(panel).getByRole('button', { name: '소멸 근거 조사 실행' })).toBeDisabled();
  expect(within(panel).queryByRole('button', { name: '조사 증거 해제' })).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: '검사 결과' })).toBeInTheDocument();
});

it('늦은 해제 실패는 새로운 조사 Run의 안내를 덮어쓰지 않는다', async () => {
  const user = await start();
  let rejectRelease!: (error: Error) => void;
  release = () => new Promise((_resolve, reject) => { rejectRelease = reject; });
  await user.click(screen.getByRole('button', { name: '조사 증거 해제' }));
  await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 시작/ }));
  await user.click(screen.getByRole('button', { name: '검사 실행' }));
  await screen.findByText('현재 응답에 서버 조사 증거가 연결됐습니다.');
  rejectRelease(new Error('synthetic_late_failure'));
  await vi.waitFor(() => expect(screen.queryByText(/서버 증거 해제를 확인하지 못했습니다/)).not.toBeInTheDocument());
});

it('Session과 두 Run의 일부 해제가 실패해도 나머지는 시도하고 Map을 무효화한다', async () => {
  const user = await start(false);
  await user.click(screen.getByRole('button', { name: '현재 결과를 비교 기준으로 저장' }));
  await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 시작/ }));
  await user.click(screen.getByRole('button', { name: '검사 실행' }));
  await screen.findByText('현재 응답에 서버 조사 증거가 연결됐습니다.');
  await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 결과/ }));
  await user.click(screen.getByText('검사 결과 비교'));
  await user.click(screen.getByRole('button', { name: '소멸 근거 조사 실행' }));
  await screen.findByRole('region', { name: 'Security Evidence Gap Map' });
  const kinds: string[] = [];
  release = async (init) => {
    kinds.push(JSON.parse(String(init.body)).kind);
    return kinds.length === 2 ? json({ error: 'internal_error' }, 500) : new Response(null, { status: 204 });
  };
  await user.click(screen.getByRole('button', { name: '조사 증거 해제' }));
  await within(screen.getByRole('region', { name: '소멸 근거 조사' })).findByRole('alert');
  expect(kinds).toEqual(['investigation', 'run', 'run']);
  expect(screen.queryByRole('region', { name: 'Security Evidence Gap Map' })).not.toBeInTheDocument();
});
