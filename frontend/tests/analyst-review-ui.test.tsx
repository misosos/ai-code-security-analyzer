import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
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
    expect(screen.getByLabelText('분석가 검토 상태')).toHaveValue('all');
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
    await user.selectOptions(screen.getByLabelText('분석가 검토 상태'), 'reviewed');
    expect(list).toHaveTextContent('baseline.rule-1'); expect(list).not.toHaveTextContent('baseline.rule-2');
    expect(screen.getByLabelText('선택한 Finding 상세')).toHaveTextContent('현재 선택한 항목은 필터에서 제외되었습니다');
    expect(within(list).getByRole('button', { name: /baseline\.rule-1/ })).toHaveAttribute('aria-pressed', 'false');
    await user.selectOptions(screen.getByLabelText('분석가 검토 상태'), 'needs_followup');
    await user.selectOptions(screen.getByLabelText('심각도'), 'critical');
    expect(list).toHaveTextContent('검색 또는 필터와 일치하는 결과가 없습니다');
    await user.selectOptions(screen.getByLabelText('심각도'), 'all');
    expect(within(list).getByRole('button', { name: /rule-2/ })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('분석가 검토 상태'), 'all');
    await user.click(within(list).getByRole('button', { name: /baseline\.rule-1/ }));
    expect(screen.getByLabelText('분석가 메모')).toHaveValue('첫 번째 메모');
  });

  it('새 검사 취소 시 기존 메모를 보존하고 확인 후에만 초기화한다', async () => {
    const first = finding('1'); installApi([scan([first]), scan([finding('1')])]);
    const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.click(screen.getByRole('button', { name: '비교 기준으로 지정' }));
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
    expect(screen.getByLabelText('분석가 검토 상태')).toHaveValue('all');
    expect(screen.getByLabelText('선택한 Finding 상세')).toHaveTextContent('검토 대기');
    expect(screen.getByRole('heading', { name: '검사 결과 비교' })).toBeInTheDocument();
  });

  it('결과 삭제 취소는 기록을 유지하고 확인 후 결과·기준·검토 기록을 함께 지운다', async () => {
    installApi([scan([finding('1')])]); const user = userEvent.setup(); render(<App/>); await screen.findByText('API 연결됨'); await performScan(user);
    await user.click(screen.getByRole('button', { name: '비교 기준으로 지정' }));
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
