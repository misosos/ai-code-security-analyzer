import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { App } from '../src/app/App';

const options = { targets: [{ id: 'target-a', label: '합성 프로젝트' }], rule_profiles: [{ id: 'baseline', label: '기본 규칙', experimental: false }] };
const finding = (id: string): ApiFinding => ({ finding_id: `semgrep:${id.padStart(24, '0').slice(-24)}`, rule_id: `baseline.rule-${id}`, severity: 'high', verification_status: 'unverified', finding_kind: 'pattern', file_path: `src/${id}.js`, line_number: 4, evidence_validation_status: 'validated', supported_claims: ['match_reported'], restricted_claims: [], validation_error_code: null });
const scan = (findings: ApiFinding[]): ScanResponse => ({ scan_status: 'completed', completed: true, semgrep_version: '1.182.1', finding_count: findings.length, displayed_finding_count: findings.length, omitted_finding_count: 0, severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 }, issues: [], findings, limitations: ['finding_count_not_confirmed_vulnerability_count'] });
function json(data: unknown) { return new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } }); }
function installApi(results: ScanResponse[]) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
    if (url.endsWith('/options')) return json(options);
    if (url.endsWith('/scans')) { const next = results.shift(); if (!next) throw new Error('unexpected scan request'); return json(next); }
    throw new Error('unexpected request');
  });
}
async function performScan(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: '검사 시작' }));
  if ((screen.getByLabelText('로컬 API 토큰') as HTMLInputElement).value === '') await user.type(screen.getByLabelText('로컬 API 토큰'), 'synthetic-review-token');
  await user.click(screen.getByRole('button', { name: '검사 실행' }));
  await screen.findByRole('heading', { name: '정상 완료' });
}

describe('분석가 Finding 검토 UI', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); vi.spyOn(Storage.prototype, 'setItem'); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it('검토 우선순위를 설명하고 단계별 절차를 제공하되 분석가 상태나 검사 응답을 바꾸지 않는다', async () => {
    const row = { ...finding('1'), rule_id: 'baseline.javascript-dynamic-eval' };
    const response = scan([row]);
    installApi([response]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨'); await performScan(user);
    const detail = screen.getByLabelText('선택한 Finding 상세');
    const guide = within(detail).getByRole('region', { name: '분석가 검토 가이드' });
    expect(guide).toHaveTextContent('우선 코드 검토 권장');
    expect(guide).toHaveTextContent('high');
    expect(guide).toHaveTextContent('실제 취약점 여부와 악용 가능성은 추가 확인이 필요합니다');
    expect(guide).toHaveTextContent('검토 작업 제안이며 위험 점수');
    await user.click(within(guide).getByText('판단 근거, 단계별 검토 절차 및 권장 조치'));
    expect(guide).toHaveTextContent('eval');
    expect(guide).toHaveTextContent('외부 입력이 인자 값을 제어할 수 있는지');
    expect(guide).toHaveTextContent('JSON 파싱');
    await user.selectOptions(within(detail).getByLabelText('수동 검토 상태'), 'reviewed');
    expect(guide).toHaveTextContent('우선 코드 검토 권장');
    expect(row.verification_status).toBe('unverified');
    expect(response.findings[0]).toEqual(row);
    expect(vi.mocked(fetch).mock.calls.filter((call) => String(call[0]).endsWith('/scans'))).toHaveLength(1);
  });

  it('근거 연결 확인 필요를 High 심각도와 함께 표시하고 위험이 낮다고 해석하지 않는다', async () => {
    const row = { ...finding('1'), evidence_validation_status: 'rejected' as const };
    installApi([scan([row])]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨'); await performScan(user);
    const guide = within(screen.getByLabelText('선택한 Finding 상세')).getByRole('region', { name: '분석가 검토 가이드' });
    expect(guide).toHaveTextContent('근거 연결 확인 필요');
    expect(guide).toHaveTextContent('높음');
    expect(guide).toHaveTextContent('위험도가 낮다는 뜻은 아닙니다');
    expect(guide).toHaveTextContent('근거 연결이 검증되지 않아 지원된 근거를 표시하지 않습니다');
  });

  it('Finding 상태와 메모를 세션 메모리에만 보관하고 API 판정과 DOM을 변경하지 않는다', async () => {
    const rows = [finding('1'), finding('2')];
    installApi([scan(rows)]);
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('API 연결됨'); await performScan(user);
    expect(screen.getByLabelText('Finding 목록')).toHaveTextContent('분석가: 검토 대기');
    const detail = screen.getByLabelText('선택한 Finding 상세');
    await user.selectOptions(within(detail).getByLabelText('수동 검토 상태'), 'needs_followup');
    await user.type(within(detail).getByLabelText('분석가 메모'), '<img src=x onerror=alert(1)> 수동 확인');
    expect(within(detail).getByText(/분석가 메모/)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    expect(detail).toHaveTextContent('추가 확인 필요');
    expect(detail).toHaveTextContent('미검증 후보');
    expect(screen.getByLabelText('Finding 목록')).toHaveTextContent('분석가: 추가 확인 필요');
    expect(screen.getByRole('heading', { name: '분석가 검토 현황' }).parentElement?.parentElement).toHaveTextContent('검토 대기');
    expect(screen.getByRole('combobox', { name: '분석가 검토' })).toHaveValue('all');
    expect(localStorage.setItem).not.toHaveBeenCalled(); expect(sessionStorage.setItem).not.toHaveBeenCalled();
    expect(vi.mocked(fetch).mock.calls.filter((call) => String(call[0]).endsWith('/scans'))).toHaveLength(1);
  });

  it('메모와 상태는 Finding별로 독립 유지되고 기존 필터와 검토 상태 필터가 함께 적용된다', async () => {
    const rows = [finding('1'), finding('2')]; installApi([scan(rows)]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    const list = screen.getByLabelText('Finding 목록');
    await user.click(within(list).getByRole('button', { name: /baseline\.rule-1/ }));
    const detail = screen.getByLabelText('선택한 Finding 상세');
    await user.selectOptions(within(detail).getByLabelText('수동 검토 상태'), 'reviewed');
    await user.type(within(detail).getByLabelText('분석가 메모'), '첫 번째 메모');
    await user.click(within(list).getByRole('button', { name: /baseline\.rule-2/ }));
    expect(within(screen.getByLabelText('선택한 Finding 상세')).getByLabelText('수동 검토 상태')).toHaveValue('pending');
    await user.selectOptions(screen.getByLabelText('수동 검토 상태'), 'needs_followup');
    await user.type(screen.getByLabelText('분석가 메모'), '두 번째 메모');
    await user.selectOptions(screen.getByRole('combobox', { name: '분석가 검토' }), 'reviewed');
    expect(list).toHaveTextContent('baseline.rule-1'); expect(list).not.toHaveTextContent('baseline.rule-2');
    expect(screen.getByLabelText('선택한 Finding 상세')).toHaveTextContent('현재 선택한 항목은 필터에서 제외되었습니다');
    expect(within(list).getByRole('button', { name: /baseline\.rule-1/ })).toHaveAttribute('aria-pressed', 'false');
    await user.selectOptions(screen.getByRole('combobox', { name: '분석가 검토' }), 'needs_followup');
    await user.selectOptions(screen.getByLabelText('심각도'), 'critical');
    expect(list).toHaveTextContent('검색 또는 필터와 일치하는 결과가 없습니다');
    await user.selectOptions(screen.getByLabelText('심각도'), 'all');
    expect(within(list).getByRole('button', { name: /rule-2/ })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: '분석가 검토' }), 'all');
    await user.click(within(list).getByRole('button', { name: /baseline\.rule-1/ }));
    expect(screen.getByLabelText('분석가 메모')).toHaveValue('첫 번째 메모');
  });

  it('새 검사 취소 시 기존 메모를 보존하고 확인 후에만 초기화한다', async () => {
    const first = finding('1'); installApi([scan([first]), scan([finding('1')])]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.click(screen.getByRole('button', { name: /비교 기준/ }));
    await user.type(screen.getByLabelText('분석가 메모'), '보존되어야 하는 노트');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await user.click(screen.getByRole('button', { name: '검사 시작' }));
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
    expect(confirm).toHaveBeenCalledOnce();
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 결과/ }));
    expect(screen.getByLabelText('분석가 메모')).toHaveValue('보존되어야 하는 노트');
    expect(vi.mocked(fetch).mock.calls.filter((call) => String(call[0]).endsWith('/scans'))).toHaveLength(1);
    confirm.mockReturnValue(true);
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: '검사 시작' }));
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
    expect(await screen.findByRole('heading', { name: '정상 완료' })).toBeInTheDocument();
    expect(vi.mocked(fetch).mock.calls.filter((call) => String(call[0]).endsWith('/scans'))).toHaveLength(2);
    expect(screen.queryByDisplayValue('보존되어야 하는 노트')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: '분석가 검토' })).toHaveValue('all');
    expect(screen.getByLabelText('선택한 Finding 상세')).toHaveTextContent('검토 대기');
    expect(screen.getByRole('heading', { name: '검사 결과 비교' })).toBeInTheDocument();
  });

  it('결과 삭제 취소는 기록을 유지하고 확인 후 결과·기준·검토 기록을 함께 지운다', async () => {
    installApi([scan([finding('1')])]); const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.click(screen.getByRole('button', { name: /비교 기준/ }));
    await user.type(screen.getByLabelText('분석가 메모'), '삭제 확인 메모');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await user.click(screen.getByRole('button', { name: '결과 지우기' }));
    expect(screen.getByLabelText('분석가 메모')).toHaveValue('삭제 확인 메모');
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole('button', { name: '결과 지우기' }));
    expect(screen.queryByLabelText('분석가 메모')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '검사 결과 비교' })).not.toBeInTheDocument();
  });

  it('메모 UTF-8 제한 초과를 거부하고 기존 메모를 보존한다', async () => {
    installApi([scan([finding('1')])]); const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    const note = screen.getByLabelText('분석가 메모') as HTMLTextAreaElement;
    await user.type(note, '유효 메모');
    fireEvent.change(note, { target: { value: '가'.repeat(683) } });
    expect(await screen.findByRole('alert')).toHaveTextContent('UTF-8 기준 2 KiB');
    expect(note).toHaveValue('유효 메모');
  });

  it('검토 현황은 생략 항목을 집계하지 않고 표시 범위를 설명한다', async () => {
    const onlyDisplayed = finding('1');
    const response = { ...scan([onlyDisplayed]), finding_count: 3, displayed_finding_count: 1, omitted_finding_count: 2, severity_counts: { critical: 0, high: 3, medium: 0, low: 0, info: 0 } };
    installApi([response]); const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    const summary = screen.getByRole('region', { name: '분석가 검토 현황' });
    expect(summary).toHaveTextContent('현재 응답 · 1건');
    expect(summary).toHaveTextContent('검토 대기1건');
    expect(summary).toHaveTextContent('생략된 2개는 포함하지 않습니다');
  });
});

describe('새 검사 시 분석가 검토 기록 보호', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); vi.spyOn(Storage.prototype, 'setItem'); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
  type ScanReply = ScanResponse | Error | Promise<Response>;
  function installReplies(replies: ScanReply[]) {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/health')) return json({ status: 'ok', service: 'ai-code-security-analyzer' });
      if (url.endsWith('/options')) return json(options);
      if (url.endsWith('/scans')) {
        const next = replies.shift();
        if (!next) throw new Error('unexpected scan request');
        if (next instanceof Error) throw next;
        if (next instanceof Promise) return next;
        return json(next);
      }
      throw new Error('unexpected request');
    });
  }
  const scanRequests = () => vi.mocked(fetch).mock.calls.filter((call) => String(call[0]).endsWith('/scans')).length;
  async function startRescan(user: ReturnType<typeof userEvent.setup>) {
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: '검사 시작' }));
    await user.click(screen.getByRole('button', { name: '검사 실행' }));
  }

  it('검토 기록이 없으면 확인 없이 새 검사를 실행한다', async () => {
    installReplies([scan([finding('1')]), scan([finding('2')])]);
    const confirm = vi.spyOn(window, 'confirm');
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await startRescan(user);
    expect(await screen.findByRole('button', { name: /baseline\.rule-2/ })).toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
    expect(scanRequests()).toBe(2);
  });

  it('검토 상태만 있어도 경고하고, 취소하면 기록을 유지한 채 기존 백업 도구로 안내한다', async () => {
    installReplies([scan([finding('1')])]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.selectOptions(screen.getByLabelText('수동 검토 상태'), 'needs_followup');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await startRescan(user);
    expect(confirm).toHaveBeenCalledOnce();
    const warning = confirm.mock.calls[0][0] as string;
    expect(warning).toContain('이전 검사의 Finding에 연결');
    expect(warning).toContain('새 검사 결과로 옮겨지지 않습니다');
    expect(warning).toContain('검토 기록 백업 JSON 다운로드');
    expect(scanRequests()).toBe(1);
    const backupButton = await screen.findByRole('button', { name: '검토 기록 백업 JSON 다운로드' });
    await waitFor(() => expect(backupButton).toHaveFocus());
    expect(backupButton.closest('details')).toHaveProperty('open', true);
    const status = within(backupButton.closest('details')!).getByRole('status');
    expect(status).toHaveTextContent('새 검사를 취소했습니다');
    expect(status).not.toHaveTextContent('다운로드했습니다');
    expect(screen.getByLabelText('수동 검토 상태')).toHaveValue('needs_followup');
  });

  it('취소 후 백업을 내려받고 명시적으로 계속하면 초기화되며, 백업은 새 결과에 수동으로만 복원된다', async () => {
    const shared = finding('1');
    installReplies([scan([shared, finding('2')]), scan([finding('1'), finding('2')]), scan([finding('1'), finding('3')])]);
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:backup-test'); vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.click(within(screen.getByRole('region', { name: 'Finding 목록' })).getByRole('button', { name: /baseline\.rule-1/ }));
    await user.selectOptions(screen.getByLabelText('수동 검토 상태'), 'reviewed');
    await user.type(screen.getByLabelText('분석가 메모'), '백업 대상 메모');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await startRescan(user);
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole('checkbox', { name: 'JSON 백업에 메모 포함' }));
    await user.click(await screen.findByRole('button', { name: '검토 기록 백업 JSON 다운로드' }));
    expect(create).toHaveBeenCalledOnce();
    const backupJson = await (create.mock.calls[0][0] as Blob).text();
    expect(JSON.parse(backupJson).findings).toEqual(expect.arrayContaining([expect.objectContaining({ finding_id: shared.finding_id, review_status: 'reviewed', note: '백업 대상 메모' })]));
    expect(screen.getByText(/검토 기록 백업을 다운로드했습니다/)).toBeInTheDocument();

    confirm.mockClear();
    await startRescan(user);
    expect(confirm).toHaveBeenCalledOnce();
    expect(await screen.findByRole('heading', { name: '정상 완료' })).toBeInTheDocument();
    expect(scanRequests()).toBe(2);
    expect(screen.queryByDisplayValue('백업 대상 메모')).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Finding 목록' })).not.toHaveTextContent('분석가: 검토 완료');

    await user.click(screen.getByText('검토 기록 백업 및 복원'));
    await user.upload(screen.getByLabelText('검토 기록 불러오기(JSON)'), new File([backupJson], 'backup.json', { type: 'application/json' }));
    const preview = await screen.findByRole('region', { name: '검토 기록 복원 미리보기' });
    expect(screen.getByRole('region', { name: 'Finding 목록' })).not.toHaveTextContent('분석가: 검토 완료');
    await user.click(within(preview).getByText(/Finding별 기록 확인/));
    await user.click(within(within(preview).getByText(shared.rule_id).closest('li')!).getByRole('button', { name: '이 기록 적용' }));
    await user.click(within(screen.getByRole('region', { name: 'Finding 목록' })).getByRole('button', { name: /baseline\.rule-1/ }));
    expect(screen.getByLabelText('수동 검토 상태')).toHaveValue('reviewed');
    expect(screen.getByLabelText('분석가 메모')).toHaveValue('백업 대상 메모');

    await startRescan(user);
    expect(await screen.findByRole('button', { name: /baseline\.rule-3/ })).toBeInTheDocument();
    await user.click(screen.getByText('검토 기록 백업 및 복원'));
    await user.upload(screen.getByLabelText('검토 기록 불러오기(JSON)'), new File([backupJson], 'backup.json', { type: 'application/json' }));
    const blocked = await screen.findByRole('region', { name: '검토 기록 복원 미리보기' });
    expect(within(blocked).getByRole('alert')).toHaveTextContent('복원 차단');
    expect(within(blocked).queryByRole('button', { name: '이 기록 적용' })).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Finding 목록' })).not.toHaveTextContent('분석가: 검토 완료');
  });

  const partial = (findings: ApiFinding[]): ScanResponse => ({ ...scan(findings), scan_status: 'partial', completed: false });
  const executionFailed = (): ScanResponse => ({ ...scan([]), scan_status: 'execution_failed', completed: false });
  const openResults = (user: ReturnType<typeof userEvent.setup>) => user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: /검사 결과/ }));
  async function reviewFirstFinding(user: ReturnType<typeof userEvent.setup>, note: string) {
    await user.selectOptions(screen.getByLabelText('수동 검토 상태'), 'needs_followup');
    await user.type(screen.getByLabelText('분석가 메모'), note);
  }
  function expectRetainedReview(note: string) {
    expect(screen.getByText(/마지막 새 검사 결과는 적용되지 않았습니다/)).toHaveAttribute('role', 'note');
    expect(screen.getByLabelText('수동 검토 상태')).toHaveValue('needs_followup');
    expect(screen.getByLabelText('분석가 메모')).toHaveValue(note);
    expect(screen.getByRole('heading', { name: '정상 완료' })).toBeInTheDocument();
  }

  it('확인 문구는 정상 완료 시에만 기록이 지워지고 실패·부분 검사에는 유지된다고 안내한다', async () => {
    installReplies([scan([finding('1')])]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await reviewFirstFinding(user, '문구 확인 메모');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await startRescan(user);
    const warning = confirm.mock.calls[0][0] as string;
    expect(warning).not.toContain('검사 성공 여부와 관계없이');
    expect(warning).toContain('새 검사가 정상 완료되면 이 기록은 화면에서 지워지고');
    expect(warning).toContain('실패하거나 일부만 완료되면 새 결과를 적용하지 않고 이전 결과와 기록을 유지');
  });

  it('새 검사 요청이 실패하면 이전 결과와 검토 기록을 그대로 복원하고 이전 결과임을 표시한다', async () => {
    installReplies([scan([finding('1')]), new TypeError('network down')]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await reviewFirstFinding(user, '실패 시 메모');
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await startRescan(user);
    const failure = await screen.findByText(/이전 검사 결과와 분석가 검토 기록을 그대로 유지했습니다/, { selector: '.request-feedback' });
    expect(failure).toHaveAttribute('role', 'alert');
    expect(failure).not.toHaveTextContent('지워졌');
    expect(scanRequests()).toBe(2);
    await openResults(user);
    expectRetainedReview('실패 시 메모');
    expect(screen.getByRole('region', { name: 'Finding 목록' })).toHaveTextContent('baseline.rule-1');
  });

  it('부분 검사 응답은 검토 기록이 있으면 적용하지 않고 비교 가능하거나 완료된 결과로 취급하지 않는다', async () => {
    installReplies([scan([finding('1')]), partial([finding('7')])]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.click(screen.getByRole('button', { name: /비교 기준/ }));
    await reviewFirstFinding(user, '부분 검사 메모');
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await startRescan(user);
    expect(await screen.findByText(/새 검사가 부분 검사로 끝나 결과를 적용하지 않았습니다/, { selector: '.request-feedback' })).toBeInTheDocument();
    expectRetainedReview('부분 검사 메모');
    expect(screen.getByRole('region', { name: 'Finding 목록' })).not.toHaveTextContent('baseline.rule-7');
    expect(screen.queryByRole('heading', { name: '부분 검사' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '검사 결과 비교' })).toBeInTheDocument();
    expect(scanRequests()).toBe(2);
  });

  it('실행 실패 상태 응답도 이전 결과와 검토 기록을 대체하지 않는다', async () => {
    installReplies([scan([finding('1')]), executionFailed()]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await reviewFirstFinding(user, '실행 실패 메모');
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await startRescan(user);
    expect(await screen.findByText(/새 검사가 실행 실패로 끝나 결과를 적용하지 않았습니다/, { selector: '.request-feedback' })).toBeInTheDocument();
    expectRetainedReview('실행 실패 메모');
  });

  it('검토 기록이 없으면 부분 검사 결과를 기존처럼 부분 검사로 표시한다', async () => {
    installReplies([scan([finding('1')]), partial([finding('7')])]);
    const confirm = vi.spyOn(window, 'confirm');
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await startRescan(user);
    expect(await screen.findByRole('heading', { name: '부분 검사' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Finding 목록' })).toHaveTextContent('baseline.rule-7');
    expect(screen.queryByText(/마지막 새 검사 결과는 적용되지 않았습니다/)).not.toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
  });

  it('복원된 기록은 다음 정상 완료 검사에서 같은 Finding ID라도 새 결과로 옮겨지지 않는다', async () => {
    installReplies([scan([finding('1')]), new TypeError('network down'), scan([finding('1')])]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await reviewFirstFinding(user, '옮겨지면 안 되는 메모');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await startRescan(user);
    await screen.findByText(/그대로 유지했습니다/, { selector: '.request-feedback' });
    await openResults(user);
    expectRetainedReview('옮겨지면 안 되는 메모');
    await startRescan(user);
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(await screen.findByRole('heading', { name: '정상 완료' })).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText(/마지막 새 검사 결과는 적용되지 않았습니다/)).not.toBeInTheDocument());
    expect(screen.queryByDisplayValue('옮겨지면 안 되는 메모')).not.toBeInTheDocument();
    expect(screen.getByLabelText('수동 검토 상태')).toHaveValue('pending');
  });

  it('복원 후 결과 지우기를 확인하면 복원 표시와 기록을 함께 지운다', async () => {
    installReplies([scan([finding('1')]), new TypeError('network down')]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await reviewFirstFinding(user, '지울 메모');
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await startRescan(user);
    await screen.findByText(/그대로 유지했습니다/, { selector: '.request-feedback' });
    await openResults(user);
    await user.click(screen.getByRole('button', { name: '결과 지우기' }));
    expect(screen.getByRole('heading', { name: '아직 검사 결과가 없습니다.' })).toBeInTheDocument();
    expect(screen.queryByText(/마지막 새 검사 결과는 적용되지 않았습니다/)).not.toBeInTheDocument();
  });

  it('검사 중 반복 실행 후 대기 중인 요청이 실패해도 기록을 한 번만 확인하고 복원한다', async () => {
    let fail: (error: Error) => void = () => {};
    const pending = new Promise<Response>((_, reject) => { fail = reject; });
    installReplies([scan([finding('1')]), pending]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await reviewFirstFinding(user, '대기 중 실패 메모');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: '검사 시작' }));
    const submit = screen.getByRole('button', { name: '검사 실행' }).closest('form')!;
    fireEvent.submit(submit); fireEvent.submit(submit);
    expect(confirm).toHaveBeenCalledOnce();
    await waitFor(() => expect(scanRequests()).toBe(2));
    fail(new TypeError('network down'));
    await screen.findByText(/그대로 유지했습니다/, { selector: '.request-feedback' });
    await openResults(user);
    expectRetainedReview('대기 중 실패 메모');
    expect(scanRequests()).toBe(2);
  });

  it('검토 기록 없이 실패한 검사는 기록 삭제 문구를 붙이지 않는다', async () => {
    installReplies([scan([finding('1')]), new TypeError('network down')]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await startRescan(user);
    const failure = await screen.findByRole('alert');
    expect(failure).not.toHaveTextContent('검토 기록');
  });

  it('검사 중 반복 실행은 경고를 우회하거나 두 번째 요청을 보내지 않는다', async () => {
    let release: (response: Response) => void = () => {};
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    installReplies([scan([finding('1')]), pending]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.type(screen.getByLabelText('분석가 메모'), '반복 클릭 메모');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await user.click(within(screen.getByRole('navigation', { name: '화면 이동' })).getByRole('button', { name: '검사 시작' }));
    const submit = screen.getByRole('button', { name: '검사 실행' }).closest('form')!;
    fireEvent.submit(submit); fireEvent.submit(submit);
    expect(confirm).toHaveBeenCalledOnce();
    await waitFor(() => expect(scanRequests()).toBe(2));
    expect(screen.getByRole('button', { name: /검사 중/ })).toBeDisabled();
    release(json(scan([finding('9')])));
    expect(await screen.findByRole('button', { name: /baseline\.rule-9/ })).toBeInTheDocument();
    expect(scanRequests()).toBe(2);
  });
});
