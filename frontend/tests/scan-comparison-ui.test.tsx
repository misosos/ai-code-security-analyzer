import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { App } from '../src/app/App';

const options = {
  targets: [{ id: 'project-a', label: 'Project A' }, { id: 'project-b', label: 'Project B' }],
  rule_profiles: [{ id: 'baseline', label: 'Baseline Rules', experimental: false }, { id: 'experimental', label: 'Experimental Rules', experimental: true }],
};

const finding = (id: string, overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: `semgrep:${Array.from(id, (char) => char.codePointAt(0)!.toString(16)).join('').padStart(24, '0').slice(-24)}`, rule_id: `baseline.${id}`,
  severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/${id}.js`, line_number: 7,
  evidence_validation_status: 'validated', supported_claims: ['match_reported'],
  restricted_claims: [{ claim_type: 'vulnerability_confirmed', decision: 'unsupported_claim', reason_codes: ['independent_confirmation_required'] }],
  validation_error_code: null, ...overrides,
});

const scan = (findings: ApiFinding[] = [], overrides: Partial<ScanResponse> = {}): ScanResponse => ({
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length,
  displayed_finding_count: findings.length, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
  issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'], ...overrides,
});

function json(data: unknown, status = 200) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }); }
function installApi(responses: Array<ScanResponse | Response>) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
    if (url.endsWith('/options')) return json(options);
    if (url.endsWith('/scans')) {
      const response = responses.shift();
      if (!response) throw new Error('unexpected scan request');
      return response instanceof Response ? response : json(response);
    }
    throw new Error('unexpected request');
  });
}

async function runScan(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: '검사 시작' }));
  await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-comparison-token');
  await user.click(screen.getByRole('button', { name: '검사 실행' }));
  await screen.findByRole('heading', { name: '정상 완료' });
}

describe('검사 결과 비교 UI', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); vi.spyOn(Storage.prototype, 'setItem'); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it('기준 저장은 명시적 클릭만 수행하고 이후 검사에서 ID별 관찰 차이와 기존 근거를 보여준다', async () => {
    const shared = finding('shared');
    const beforeOnly = finding('before');
    const afterOnly = finding('after');
    installApi([scan([shared, beforeOnly]), scan([afterOnly, shared])]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await runScan(user);
    expect(screen.getByRole('heading', { name: '검사 결과 비교' })).toBeInTheDocument();
    expect(screen.getByText(/비교 기준이 없습니다/)).toBeInTheDocument();
    expect(screen.queryByText(/양쪽에서 관찰/)).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '비교 기준으로 지정' }));
    expect(screen.getByText(/기준 지정 직후/)).toBeInTheDocument();
    await runScan(user);

    await user.click(screen.getByText('검사 결과 비교'));
    const counts = screen.getByLabelText('Finding 관찰 차이');
    expect(within(counts).getByText('이번 검사에서만 관찰').parentElement).toHaveTextContent('1');
    expect(within(counts).getByText('양쪽에서 관찰').parentElement).toHaveTextContent('1');
    expect(within(counts).getByText('기준 검사에서만 관찰').parentElement).toHaveTextContent('1');
    expect(screen.getByText(/취약점의 신규 발생이나 해결을 확정하지 않습니다/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /기준 검사에서만 관찰/ }));
    const baselineList = screen.getByRole('region', { name: '기준 검사에서만 관찰 목록' });
    await user.click(within(baselineList).getByRole('button', { name: /src\/before\.js:7/ }));
    expect(screen.getByRole('region', { name: '비교 항목 근거' })).toHaveTextContent('중요한 제한');
    expect(screen.getByRole('region', { name: '비교 항목 근거' })).toHaveTextContent('취약점으로 확정되지 않았습니다');
  });

  it('대상·프로필·버전 문맥이 맞지 않거나 결과가 생략되면 비교를 차단한다', async () => {
    installApi([scan([finding('one')]), scan([finding('two')])]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨'); await runScan(user);
    await user.click(screen.getByRole('button', { name: '비교 기준으로 지정' }));
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: '검사 시작' }));
    await user.selectOptions(screen.getByLabelText('검사 대상'), 'project-b');
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
    await screen.findByRole('heading', { name: '정상 완료' });
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 결과/ }));
    expect(screen.getByText('검사 대상이 서로 다릅니다.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Finding 관찰 차이')).not.toBeInTheDocument();
  });

  it('재검사가 HTTP 오류면 이전 현재 결과를 재사용하지 않고 기준만 남긴다', async () => {
    installApi([scan([finding('one')]), json({ error: 'internal_error' }, 500)]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨'); await runScan(user);
    await user.click(screen.getByRole('button', { name: '비교 기준으로 지정' }));
    await user.click(screen.getByRole('button', { name: '검사 시작' }));
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-comparison-token');
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
    await screen.findByRole('alert');
    await user.click(screen.getByRole('button', { name: '검사 결과' }));
    expect(screen.getByText(/비교할 현재 검사가 없습니다/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '정상 완료' })).not.toBeInTheDocument();
  });

  it('결과 지우기는 기준과 현재를 함께 비우고 API 텍스트는 HTML로 해석하지 않는다', async () => {
    const dangerousLabel = 'Project <img src=x onerror=alert(1)>';
    installApi([scan([finding('one', { file_path: 'src/<img onerror=alert(1)>.js' })])]);
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
      if (url.endsWith('/options')) return json({ targets: [{ id: 'project-a', label: dangerousLabel }], rule_profiles: options.rule_profiles });
      if (url.endsWith('/scans')) return json(scan([finding('one', { file_path: 'src/<img onerror=alert(1)>.js' })]));
      throw new Error('unexpected request');
    });
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨'); await runScan(user);
    expect(screen.getByText(dangerousLabel)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    await user.click(screen.getByRole('button', { name: '비교 기준으로 지정' }));
    await user.click(screen.getByRole('button', { name: '결과 지우기' }));
    expect(screen.queryByRole('heading', { name: '검사 결과 비교' })).not.toBeInTheDocument();
    expect(screen.getByText(/비교 기준을 지웠습니다/)).toBeInTheDocument();
    expect(localStorage.setItem).not.toHaveBeenCalled();
    expect(sessionStorage.setItem).not.toHaveBeenCalled();
  });

  it('부분 검사나 생략 결과를 기준으로 비교 완료 처리하지 않는다', async () => {
    const partial = scan([finding('one')], { scan_status: 'partial', completed: false, limitations: ['scan_partial'] });
    installApi([partial]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨');
    await user.click(screen.getByRole('button', { name: '검사 시작' }));
    await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-comparison-token');
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
    await screen.findByRole('heading', { name: '부분 검사' });
    const setBaseline = screen.getByRole('button', { name: '비교 기준으로 지정' });
    expect(setBaseline).toBeDisabled();
    expect(screen.getByText(/부분 검사 또는 실패한 결과는 비교할 수 없습니다/)).toBeInTheDocument();
  });
});
