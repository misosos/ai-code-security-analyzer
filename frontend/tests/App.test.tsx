import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../src/app/App';

const options = { targets:[{id:'local-project',label:'Local Project'},{id:'other-project',label:'Other Local Project'}], rule_profiles:[{id:'baseline',label:'Baseline Rules',experimental:false},{id:'command-injection-experimental',label:'Experimental Command Injection',experimental:true}] };
const finding = (overrides:Record<string,unknown>={}) => ({
  finding_id:'semgrep:0123456789abcdef01234567',rule_id:'experimental.command-injection',severity:'high',verification_status:'unverified',finding_kind:'taint',file_path:'src/<img src=x onerror=alert(1)>.js',line_number:8,evidence_validation_status:'validated',
  supported_claims:['match_reported','taint_rule_match_reported','source_pattern_declared','sink_pattern_declared','match_location_observed'],
  restricted_claims:[{claim_type:'source_location_identified',decision:'unavailable',reason_codes:['source_location_unknown']},{claim_type:'flow_trace_available',decision:'unavailable',reason_codes:['flow_trace_absent','source_sink_path_unproven']},{claim_type:'vulnerability_confirmed',decision:'unsupported_claim',reason_codes:['independent_confirmation_required']}],validation_error_code:null,...overrides,
});
const scan = (findings=[finding()], overrides:Record<string,unknown>={}) => ({scan_status:'completed',completed:true,semgrep_version:'1.182.1',finding_count:findings.length,displayed_finding_count:findings.length,omitted_finding_count:0,severity_counts:{critical:0,high:findings.length,medium:0,low:0,info:0},issues:[],findings,limitations:['finding_count_not_confirmed_vulnerability_count','scan_result_is_not_safety_proof'],...overrides});
function json(data:unknown,status=200){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});}
function queueScan(result:unknown){vi.mocked(fetch).mockImplementation(async (input,init) => {
  const url=String(input); if(url.endsWith('/health')) return json({status:'ok',service:'ai-code-security-analyzer'});
  if(url.endsWith('/options')) return json(options);
  if(url.endsWith('/scans')) { expect(new Headers(init?.headers).get('X-Local-API-Token')).toBe('test-local-token-which-is-not-persisted'); return json(result); }
  throw new Error('unexpected_url');
});}

describe('Analyst dashboard',()=>{
  beforeEach(()=>{vi.stubGlobal('fetch',vi.fn()); vi.spyOn(Storage.prototype,'setItem');});
  afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.restoreAllMocks();});

  it('shows a beginner quick start even when the API is offline',async()=>{
    vi.mocked(fetch).mockRejectedValue(new Error('offline'));
    const user=userEvent.setup(); render(<App/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('로컬 API에 연결할 수 없습니다');
    const quickStart=screen.getByText('처음 시작하기').closest('details')!;
    expect(quickStart).toBeInTheDocument(); expect(quickStart).not.toHaveAttribute('open');
    await user.click(screen.getByText('처음 시작하기'));
    expect(quickStart).toHaveAttribute('open');
    expect(within(quickStart).getByText(/AI_CODE_SECURITY_TARGETS/)).toBeInTheDocument();
    expect(within(quickStart).getByText(/서버를 재시작해야 등록 변경이 적용됩니다/)).toBeInTheDocument();
    expect(within(quickStart).getByText(/secrets\.token_urlsafe\(48\)/)).toBeInTheDocument();
    expect(within(quickStart).getAllByText(/127\.0\.0\.1:8765/).length).toBeGreaterThan(0);
    expect(within(quickStart).getAllByText(/127\.0\.0\.1:5173/).length).toBeGreaterThan(0);
  });

  it('explains the token, allowlisted project, rule profile, and experimental scope in plain Korean',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options));
    render(<App/>); await screen.findByText(/연결됨/);
    expect(screen.getByText(/내 컴퓨터의 검사 서버에 요청할 권한/)).toBeInTheDocument();
    expect(screen.getByText(/GitHub에 커밋하거나 다른 사람과 공유하지 마세요/)).toBeInTheDocument();
    expect(screen.getByText(/토큰을 지우면 화면의 입력값만 제거됩니다/)).toBeInTheDocument();
    expect(screen.getByText(/서버 운영자가 등록한 프로젝트만 선택/)).toBeInTheDocument();
    expect(screen.getByRole('option',{name:'Local Project (local-project)'})).toBeInTheDocument();
    expect(screen.getByText(/보안 문제.*검사 규칙 묶음/)).toBeInTheDocument();
    await userEvent.setup().selectOptions(screen.getAllByRole('combobox')[1],'command-injection-experimental');
    expect(screen.getByText(/일반적인 정확도가 충분히 검증됐다는 뜻은 아닙니다/)).toBeInTheDocument();
  });

  it('shows beginner result summaries and maps known status codes without hiding technical codes',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    queueScan(scan([finding()],{issues:['semgrep_timeout']})); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText(/보안상 확인이 필요한 코드가 발견됐습니다/)).toBeInTheDocument();
    expect(screen.getByText(/실제 취약점인지는 아직 확인되지 않았습니다/)).toBeInTheDocument();
    expect(screen.getByRole('heading',{name:'검사 시간이 초과됐습니다.'})).toBeInTheDocument();
    expect(screen.getByText(/허용된 시간 안에 검사가 끝나지 않았습니다/)).toBeInTheDocument();
    expect(screen.getByText(/프로젝트의 검사 범위와 실행 환경을 확인한 뒤 다시 검사/)).toBeInTheDocument();
    expect(screen.getByText('semgrep_timeout')).toBeInTheDocument();
  });

  it('keeps zero, partial, and failed summaries tied to the returned scan status',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    queueScan(scan([])); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText('이번 검사에서 보고된 검토 후보가 없습니다. 프로젝트가 안전하다는 뜻은 아닙니다.')).toBeInTheDocument();
    cleanup(); vi.mocked(fetch).mockReset(); vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    queueScan(scan([finding()],{scan_status:'partial',completed:false,limitations:['scan_partial'],issues:['evidence_unavailable']})); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText('검사가 일부만 완료됐습니다. 검사되지 않은 부분의 안전성은 확인할 수 없습니다.')).toBeInTheDocument();
    expect(screen.getByRole('heading',{name:'분석 근거 일부를 확인할 수 없습니다.'})).toBeInTheDocument();
    cleanup(); vi.mocked(fetch).mockReset(); vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    queueScan(scan([],{scan_status:'timed_out',completed:false,limitations:['scan_failed'],issues:['semgrep_timeout']})); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText('검사를 완료하지 못했습니다. 검사 결과로 프로젝트의 안전성을 판단하지 마세요.')).toBeInTheDocument();
  });

  it('places advanced evidence behind an accessible disclosure while keeping key limits visible',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); queueScan(scan()); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    const technical=await screen.findByText('기술 근거와 제한 자세히 보기');
    expect(technical.closest('details')).not.toHaveAttribute('open');
    expect(screen.getByText(/이 결과는 검토 후보이며 실제 취약점으로 확정되지 않았습니다/)).toBeInTheDocument();
    expect(screen.getByText(/Source\/Sink 위치와 전체 데이터 전달 경로는 확인되지 않았을 수 있습니다/)).toBeInTheDocument();
    await userEvent.setup().click(technical);
    expect(technical.closest('details')).toHaveAttribute('open');
    expect(screen.getByText('확인된 구조적 근거')).toBeInTheDocument();
    expect(screen.getByText('실제 Source 위치 정보가 제공되지 않았습니다.')).toBeInTheDocument();
  });

  it('loads actual API options, labels experimental profiles, requires a token, and sends it only in the request header',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options));
    const user=userEvent.setup(); render(<App/>);
    expect(await screen.findByText(/연결됨/)).toBeInTheDocument();
    expect(screen.getByRole('option',{name:'Experimental · Experimental Command Injection'})).toBeInTheDocument();
    const run=screen.getByRole('button',{name:'검사 실행'}); expect(run).toBeDisabled();
    await user.type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    queueScan(scan());
    await user.click(run);
    expect(await screen.findByText('검토 후보')).toBeInTheDocument();
    const request=vi.mocked(fetch).mock.calls.find((call)=>String(call[0]).endsWith('/scans'))!;
    expect(String(request[0])).not.toContain('test-local-token');
    expect(request[1]?.body).not.toContain('test-local-token');
    expect(request[1]?.credentials).toBe('omit'); expect(request[1]?.cache).toBe('no-store');
    expect(new Headers(request[1]?.headers).get('X-Local-API-Token')).toBe('test-local-token-which-is-not-persisted');
    expect(localStorage.setItem).not.toHaveBeenCalled(); expect(sessionStorage.setItem).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button',{name:'지우기'})); expect(screen.getByLabelText('로컬 API 토큰')).toHaveValue(''); expect(screen.getByRole('button',{name:'검사 실행'})).toBeDisabled();
  });

  it('separates supported and restricted evidence, keeps unverified status, and renders API strings as text',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options));
    render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); queueScan(scan());
    await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText('확인된 구조적 근거')).toBeInTheDocument();
    expect(screen.getByText('실제 Source 위치 정보가 제공되지 않았습니다.')).toBeInTheDocument();
    expect(screen.getByText(/trace가 제공되지 않았습니다/)).toBeInTheDocument();
    expect(screen.getByText(/취약점 확정에는 별도의 확인/)).toBeInTheDocument();
    expect(screen.getAllByText('미검증 후보').length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(within(screen.getByLabelText('선택한 Finding 상세')).getByText('src/<img src=x onerror=alert(1)>.js:8')).toBeInTheDocument();
  });

  it('shows partial and failed Semgrep statuses distinctly from successful HTTP responses',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    queueScan(scan([finding()],{scan_status:'partial',completed:false,limitations:['scan_partial']})); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByRole('heading',{name:'부분 검사'})).toBeInTheDocument();
    expect(screen.getByText(/검사되지 않은 부분의 안전성은 확인할 수 없습니다/)).toBeInTheDocument();
    cleanup(); vi.mocked(fetch).mockReset(); vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); queueScan(scan([],{scan_status:'timed_out',completed:false,limitations:['scan_failed']})); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByRole('heading',{name:'시간 초과'})).toBeInTheDocument(); expect(screen.getByText(/검사를 완료하지 못했습니다\. 검사 결과로 프로젝트의 안전성을 판단하지 마세요/)).toBeInTheDocument();
  });

  it('handles zero findings and filters only the returned finding set',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); queueScan(scan([])); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText('보고된 Finding이 없습니다')).toBeInTheDocument(); expect(screen.getByText(/안전하다는 증명이 아닙니다/)).toBeInTheDocument();
  });

  it('disables repeat scan submissions while the synchronous request is pending',async()=>{
    let resolveScan!:(response:Response)=>void;
    const pending=new Promise<Response>((resolve)=>{resolveScan=resolve;});
    vi.mocked(fetch).mockImplementation(async (input)=>{
      if(String(input).endsWith('/health')) return json({status:'ok',service:'ai-code-security-analyzer'});
      if(String(input).endsWith('/options')) return json(options);
      return pending;
    });
    render(<App/>); await screen.findByText(/연결됨/);
    const user=userEvent.setup(); await user.type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    await user.click(screen.getByRole('button',{name:'검사 실행'}));
    const pendingButton=screen.getByRole('button',{name:/검사 중/}); expect(pendingButton).toBeDisabled();
    expect(vi.mocked(fetch).mock.calls.filter((call)=>String(call[0]).endsWith('/scans'))).toHaveLength(1);
    resolveScan(json(scan()));
    expect(await screen.findByRole('heading',{name:'정상 완료'})).toBeInTheDocument();
  });

  it('maps auth, origin, concurrent-scan, response-limit, and connection errors without retrying',async()=>{
    for (const [status,code,message] of [[401,'unauthorized','토큰을 확인하세요'],[403,'origin_not_allowed','브라우저 출처'],[409,'scan_already_running','이미 검사가 진행 중'],[413,'response_limit_exceeded','응답이 허용 크기']] as const) {
      cleanup(); vi.mocked(fetch).mockReset(); vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):String(input).endsWith('/options')?json(options):json({error:code},status));
      render(<App/>); await screen.findByText(/연결됨/); await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
      expect(await screen.findByText(new RegExp(message))).toBeInTheDocument();
      expect(vi.mocked(fetch).mock.calls.filter((call)=>String(call[0]).endsWith('/scans'))).toHaveLength(1);
    }
  });

  it('handles internal and network failures without automatic retry',async()=>{
    for (const result of [{status:500,body:{error:'internal_error'}},{status:0,body:null}]) {
      cleanup(); vi.mocked(fetch).mockReset(); vi.mocked(fetch).mockImplementation(async (input)=>{
        if(String(input).endsWith('/health')) return json({status:'ok',service:'ai-code-security-analyzer'});
        if(String(input).endsWith('/options')) return json(options);
        if(result.status===0) throw new Error('network_failure');
        return json(result.body,result.status);
      });
      render(<App/>); await screen.findByText(/연결됨/); await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
      expect(await screen.findByText(result.status===0?'로컬 API에 연결할 수 없습니다.':'서버 내부 오류가 발생했습니다.')).toBeInTheDocument();
      expect(vi.mocked(fetch).mock.calls.filter((call)=>String(call[0]).endsWith('/scans'))).toHaveLength(1);
    }
  });

  it('preserves total and omitted counts when the API caps displayed results',async()=>{
    const findings=Array.from({length:50},(_,index)=>finding({finding_id:`semgrep:${index.toString(16).padStart(24,'0')}`}));
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); queueScan(scan(findings,{finding_count:51,displayed_finding_count:50,omitted_finding_count:1,severity_counts:{critical:0,high:51,medium:0,low:0,info:0},limitations:['finding_count_not_confirmed_vulnerability_count','scan_result_is_not_safety_proof','omitted_findings_not_individually_validated'],issues:['findings_omitted']}));
    await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText('표시된 결과')).toBeInTheDocument();
    expect(within(screen.getByText('생략된 결과').closest('.metric')!).getByText('1')).toBeInTheDocument();
    expect(screen.getByText('omitted_findings_not_individually_validated')).toBeInTheDocument();
    expect(screen.getByText(/필터는 이 응답에 표시된 최대 50건에만 적용됩니다/)).toBeInTheDocument();
  });

  it('keeps the request-time scan context when current settings change and exports only on click',async()=>{
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    const user=userEvent.setup(); await user.type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted');
    const create=vi.spyOn(URL,'createObjectURL').mockReturnValue('blob:review-test'); const revoke=vi.spyOn(URL,'revokeObjectURL').mockImplementation(()=>{});
    vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
    queueScan(scan()); await user.click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByText(/이 결과를 생성한 검사 설정/)).toBeInTheDocument();
    expect(within(screen.getByLabelText('이 결과를 생성한 검사 설정')).getByText('Baseline Rules')).toBeInTheDocument();
    await user.selectOptions(screen.getAllByRole('combobox')[1],'command-injection-experimental');
    await user.selectOptions(screen.getAllByRole('combobox')[0],'other-project');
    expect(screen.getByRole('alert')).toHaveTextContent('표시된 결과는 이전 검사 설정(Local Project · Baseline Rules)에 속합니다');
    expect(screen.getByRole('alert')).toHaveTextContent('현재 선택한 설정(Other Local Project · Experimental · Experimental Command Injection)');
    expect(screen.getByRole('heading',{name:'정상 완료'})).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button',{name:'현재 검사 결과 내보내기'}));
    expect(create).toHaveBeenCalledOnce();
    const blob=create.mock.calls[0][0] as Blob; const content=await blob.text();
    expect(content).toContain('Baseline Rules'); expect(content).not.toContain('Experimental · Command Injection');
    expect(content).toContain('Semgrep 규칙 매치 보고'); expect(content).not.toContain('test-local-token-which-is-not-persisted');
    await user.click(screen.getByRole('button',{name:'결과 지우기'}));
    expect(screen.queryByRole('heading',{name:'정상 완료'})).not.toBeInTheDocument();
    expect(screen.queryByText(/이 결과를 생성한 검사 설정/)).not.toBeInTheDocument();
    expect(screen.getByLabelText('로컬 API 토큰')).toHaveValue('test-local-token-which-is-not-persisted');
    queueScan(scan()); await user.click(screen.getByRole('button',{name:'검사 실행'}));
    expect(await screen.findByRole('heading',{name:'정상 완료'})).toBeInTheDocument();
    expect(screen.getByLabelText('심각도')).toHaveValue('all');
    await new Promise((resolve)=>setTimeout(resolve,0)); expect(revoke).toHaveBeenCalledWith('blob:review-test');
  });

  it('does not show supported claims on evidence validation failure and selects rows accessibly',async()=>{
    const findings=[finding({finding_id:'semgrep:0123456789abcdef01234567'}),finding({finding_id:'semgrep:1123456789abcdef01234567',rule_id:'baseline.test-pattern',finding_kind:'pattern',severity:'medium',evidence_validation_status:'unavailable',supported_claims:[],restricted_claims:[],validation_error_code:'evidence_unavailable'})];
    vi.mocked(fetch).mockImplementation(async (input)=>String(input).endsWith('/health')?json({status:'ok',service:'ai-code-security-analyzer'}):json(options)); render(<App/>); await screen.findByText(/연결됨/);
    await userEvent.setup().type(screen.getByLabelText('로컬 API 토큰'),'test-local-token-which-is-not-persisted'); queueScan(scan(findings)); await userEvent.setup().click(screen.getByRole('button',{name:'검사 실행'}));
    const pattern = await screen.findByRole('button',{name:/baseline.test-pattern/}); await userEvent.setup().click(pattern);
    expect(screen.getByText(/근거 검증이 통과하지 않았습니다/)).toHaveTextContent('지원된 주장은 표시하지 않습니다');
    expect(screen.getByText(/근거 연결을 검증하지 못해 지원된 근거는 표시하지 않습니다/)).toBeInTheDocument();
    expect(screen.queryByText('Semgrep 규칙 매치 보고')).not.toBeInTheDocument();
    await userEvent.setup().selectOptions(screen.getByLabelText('유형'),'pattern'); expect(within(screen.getByLabelText('Finding 목록')).getByRole('button',{name:/baseline.test-pattern/})).toBeInTheDocument();
  });
});
