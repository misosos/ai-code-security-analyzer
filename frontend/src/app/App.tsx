import { useEffect, useMemo, useState } from 'react';
import { api, ApiError } from '../api/client';
import type { ApiFinding, ClaimType, FindingKind, Options, ScanResponse, Severity } from '../api/types';
import { createReviewMarkdown, downloadReviewMarkdown, type ScanContext } from '../features/scans/markdownExport';
import { QuickStart, ScanStatusGuidance, SecurityGlossary } from './BeginnerGuidance';

type RequestState = 'ready' | 'scanning' | 'completed' | 'partial' | 'failed' | 'unauthorized' | 'scan_already_running' | 'connection_error';
const severityOrder: Severity[] = ['critical','high','medium','low','info'];
const severityLabels: Record<Severity,string> = { critical: '매우 높음', high: '높음', medium: '중간', low: '낮음', info: '정보' };
const kindLabels: Record<FindingKind,string> = { taint: '입력 흐름 분석', pattern: '코드 형태 검사', unclassified: '분류 확인 불가' };
const ruleNameLabels: Record<string,string> = {
  'baseline.javascript-dynamic-eval': 'JavaScript 동적 코드 실행',
  'baseline.react-dangerous-html': 'React HTML 직접 삽입',
  'baseline.firestore-unconditional-write': 'Firestore 조건 없는 쓰기 허용',
  'experimental.javascript-eval-taint': 'JavaScript 입력의 동적 실행',
  'experimental.javascript-eval-taint-with-synthetic-sanitizer': 'JavaScript 입력 흐름 실험 규칙',
  'experimental.javascript-command-injection-taint': 'Node.js 명령 실행 입력 흐름',
  'experimental.react-html-sink-coverage': 'React HTML 삽입 실험 규칙',
};
const ruleName = (ruleId: string) => ruleNameLabels[ruleId] ?? '보안 규칙 매치';
const claimLabels: Record<ClaimType,string> = {
  match_reported: 'Semgrep 규칙 매치 보고', taint_rule_match_reported: '신뢰된 taint 규칙 매치 보고',
  source_pattern_declared: '규칙의 Source 패턴 선언', sink_pattern_declared: '규칙의 Sink 패턴 선언',
  match_location_observed: 'Semgrep 매치 위치 관찰', source_location_identified: '실제 Source 위치 식별',
  sink_argument_location_identified: 'Sink 인자 위치 식별', flow_trace_available: '구조화된 흐름 trace 제공',
  sanitizer_match_observed: 'Sanitizer 매치 관찰', sanitizer_effectiveness_verified: 'Sanitizer 효과 검증', vulnerability_confirmed: '취약점 확정',
};
const decisionLabels: Record<string,string> = { insufficient_evidence:'근거 부족', unavailable:'현재 자료에서 확인 불가', ambiguous:'근거 연결 모호', unsupported_claim:'이 분석에서 지원하지 않는 판단' };
const reasonLabels: Record<string,string> = {
  source_location_unknown:'실제 Source 위치 정보가 제공되지 않았습니다.', source_location_unavailable:'실제 Source 위치를 확인할 수 없습니다.',
  sink_argument_location_unknown:'Sink 인자 위치 정보가 제공되지 않았습니다.', sink_argument_location_unavailable:'Sink 인자 위치를 확인할 수 없습니다.',
  match_location_not_sink_argument:'매치 위치는 Sink 인자 위치로 확인되지 않았습니다.',
  flow_trace_absent:'구조화된 데이터 흐름 trace가 제공되지 않았습니다. 흐름이 없다는 뜻은 아닙니다.', flow_trace_empty:'Trace가 비어 있습니다. 흐름이 없다는 뜻은 아닙니다.',
  sanitizer_match_unknown:'Sanitizer 적용 여부가 확인되지 않았습니다.', sanitizer_effectiveness_not_verified:'정제 함수의 실제 보안 효과는 검증되지 않았습니다.',
  independent_confirmation_required:'취약점 확정에는 별도의 확인이 필요합니다.', taint_match_not_vulnerability_confirmation:'Taint 규칙 매치는 취약점 확정이 아닙니다.',
  source_sink_path_unproven:'전체 Source→Sink 경로는 증명되지 않았습니다.', rule_declaration_not_observed_code:'규칙 선언은 실제 코드 위치의 관찰이 아닙니다.',
  rule_file_at_scan_time_unproven:'검사 시점에 사용된 규칙 파일의 원자적 동일성은 증명되지 않았습니다.',
  analysis_scope_derived_from_engine_metadata:'분석 범위는 엔진 메타데이터를 바탕으로 추정됐습니다.',
  static_evidence_cannot_support_claim:'현재 정적 근거로는 이 주장을 지원할 수 없습니다.', scan_partial:'검사가 일부만 완료됐습니다.',
  scan_not_complete:'전체 검사가 완료되지 않았습니다.', scan_failed:'검사가 실패해 매치를 확인할 수 없습니다.',
};
const taskText: Record<FindingKind,string[]> = {
  taint: ['실제 입력 출처를 코드에서 확인하세요.','위험 함수에 전달되는 인자와 변수 관계를 확인하세요.','입력 검증과 정제 로직의 구현 및 호출 순서를 확인하세요.','함수 경계 밖의 전달 흐름을 직접 검토하세요.','런타임에서 해당 코드에 도달하는 조건을 확인하세요.'],
  pattern: ['탐지된 패턴과 표시 위치의 코드를 확인하세요.','입력값과 데이터 출처를 직접 확인하세요.','주변의 입력 검증 및 방어 조건을 검토하세요.'],
  unclassified: ['규칙과 근거 연결을 확인하세요.','매치 위치와 규칙 ID를 원본 프로젝트에서 확인하세요.','분류에 필요한 근거가 누락됐는지 검토하세요.'],
};
const statusLabels: Record<string,string> = { completed:'정상 완료', partial:'부분 검사', execution_failed:'실행 실패', not_installed:'Semgrep 미설치', invalid_json:'결과 형식 오류', timed_out:'시간 초과', output_limit_exceeded:'출력 제한 초과' };
const requestStateLabels: Partial<Record<RequestState,string>> = { ready:'대기', scanning:'검사 진행 중', unauthorized:'인증 실패', scan_already_running:'이미 검사 중', connection_error:'API 연결 오류', failed:'요청 실패' };
const errorLabels: Record<string,string> = {
  unauthorized:'토큰을 확인하세요. 인증되지 않아 검사를 실행하지 않았습니다.', origin_not_allowed:'브라우저 출처가 서버 허용 목록에 없습니다. 서버의 Origin 설정을 확인하세요.',
  scan_already_running:'이미 검사가 진행 중입니다. 완료 후 다시 시도하세요.', target_not_allowed:'허용되지 않은 프로젝트입니다.', rule_profile_not_allowed:'허용되지 않은 규칙 프로필입니다.',
  response_limit_exceeded:'응답이 허용 크기를 초과했습니다.', invalid_request:'요청을 확인할 수 없습니다.', internal_error:'서버 내부 오류가 발생했습니다.',
  connection_error:'로컬 API에 연결할 수 없습니다.', invalid_api_response:'서버 응답 형식을 확인할 수 없습니다.', request_failed:'요청이 거부되었습니다.',
};
function safeError(error: unknown): { state: RequestState; message: string } {
  if (!(error instanceof ApiError)) return { state:'failed', message:'요청을 완료하지 못했습니다.' };
  const state: RequestState = error.code === 'connection_error' || error.status === 0 ? 'connection_error' : error.code === 'unauthorized' || error.status === 401 ? 'unauthorized' : error.code === 'scan_already_running' || error.status === 409 ? 'scan_already_running' : 'failed';
  return { state, message: errorLabels[error.code] ?? `요청이 거부되었습니다 (HTTP ${error.status}).` };
}

export function App() {
  const [health, setHealth] = useState<'checking'|'connected'|'offline'>('checking');
  const [options, setOptions] = useState<Options | null>(null);
  const [bootstrapError, setBootstrapError] = useState('');
  const [token, setToken] = useState('');
  const [targetId, setTargetId] = useState('');
  const [profileId, setProfileId] = useState('');
  const [state, setState] = useState<RequestState>('ready');
  const [message, setMessage] = useState('');
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [scanContext, setScanContext] = useState<ScanContext | null>(null);
  const [exportMessage, setExportMessage] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const [verificationFilter, setVerificationFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    let active = true;
    Promise.all([api.health(), api.options()]).then(([_, data]) => {
      if (!active) return;
      setHealth('connected'); setOptions(data);
      setTargetId(data.targets[0]?.id ?? ''); setProfileId(data.rule_profiles[0]?.id ?? '');
    }).catch(() => { if (active) { setHealth('offline'); setBootstrapError('로컬 API에 연결할 수 없습니다. FastAPI 서버와 허용 Origin 설정을 확인하세요.'); } });
    return () => { active = false; };
  }, []);

  const visibleFindings = useMemo(() => (scan?.findings ?? []).filter((finding) =>
    (severityFilter === 'all' || finding.severity === severityFilter) &&
    (kindFilter === 'all' || finding.finding_kind === kindFilter) &&
    (verificationFilter === 'all' || finding.verification_status === verificationFilter) &&
    (!searchQuery.trim() || [ruleName(finding.rule_id), finding.rule_id, finding.file_path ?? '', finding.line_number?.toString() ?? ''].some((value) => value.toLocaleLowerCase('ko-KR').includes(searchQuery.trim().toLocaleLowerCase('ko-KR'))))), [scan, severityFilter, kindFilter, verificationFilter, searchQuery]);
  const selected = visibleFindings.find((finding) => finding.finding_id === selectedId) ?? visibleFindings[0];

  async function runScan(event: React.FormEvent) {
    event.preventDefault();
    if (!token || !targetId || !profileId || state === 'scanning') return;
    const target = options?.targets.find((item) => item.id === targetId);
    const profile = options?.rule_profiles.find((item) => item.id === profileId);
    if (!target || !profile) return;
    const requestedContext = { targetId: target.id, targetLabel: target.label, ruleProfileId: profile.id, ruleProfileLabel: profile.label, experimental: profile.experimental };
    setState('scanning'); setMessage('검사 진행 중입니다. 실제 진행률 정보는 제공되지 않습니다.'); setScan(null); setScanContext(null); setSelectedId(''); setExportMessage(''); resetFilters();
    try {
      const result = await api.scan(token, targetId, profileId);
      setScan(result); setScanContext({ ...requestedContext, scanStatus: result.scan_status, receivedAt: new Date().toISOString() }); setState(result.scan_status === 'completed' ? 'completed' : result.scan_status === 'partial' ? 'partial' : 'failed');
      setMessage(result.scan_status === 'completed' ? 'Semgrep 검사가 정상 완료됐습니다. 결과는 취약점 확정이나 코드 안전성 증명이 아닙니다.' : result.scan_status === 'partial' ? '검사가 일부만 완료됐습니다. 누락된 영역이 있을 수 있습니다.' : `검사 응답은 수신했지만 Semgrep 상태는 ${statusLabels[result.scan_status] ?? '알 수 없음'}입니다.`);
    } catch (error) { const result = safeError(error); setState(result.state); setMessage(result.message); }
  }
  function clearToken() { setToken(''); setState('ready'); setMessage('화면에 입력한 토큰을 지웠습니다. 서버 설정의 토큰은 변경되지 않습니다.'); }
  function resetFilters() { setSeverityFilter('all'); setKindFilter('all'); setVerificationFilter('all'); setSearchQuery(''); }
  function clearResults() {
    if (state === 'scanning') return;
    setScan(null); setScanContext(null); setSelectedId(''); resetFilters(); setExportMessage(''); setMessage('화면의 검사 결과와 관련 임시 상태를 지웠습니다. 서버의 검사 취소나 다운로드 파일 삭제는 수행하지 않습니다.');
    if (state !== 'unauthorized' && state !== 'connection_error' && state !== 'scan_already_running') setState('ready');
  }
  function exportResults() {
    if (!scan || !scanContext) return;
    try { downloadReviewMarkdown(createReviewMarkdown(scanContext, scan)); setExportMessage('현재 API 응답에 포함된 Finding 요약을 다운로드했습니다.'); }
    catch { setExportMessage('요약을 내보낼 수 없습니다. 출력 크기 제한을 확인하세요.'); }
  }

  const selectedProfile = options?.rule_profiles.find((item) => item.id === profileId);
  const contextChanged = Boolean(scanContext && (targetId !== scanContext.targetId || profileId !== scanContext.ruleProfileId));
  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="#main-content" aria-label="AI Code Security Analyzer 대시보드로 이동">
        <span className="brand-emblem" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M20 2 35 11v18l-15 9L5 29V11z"/><path d="m20 9 9 5v12l-9 5-9-5V14z"/><circle cx="20" cy="20" r="3"/></svg></span>
        <span className="brand-copy"><strong>AI Code Security Analyzer</strong><small>LOCAL ANALYSIS WORKSPACE</small></span>
      </a>
      <div className="header-status" aria-label="연결 및 검사 상태">
        <span className={`status-indicator ${health}`} aria-hidden="true" />
        <span>API {health === 'connected' ? '연결됨' : health === 'checking' ? '확인 중' : '연결 안 됨'}</span>
        <span className="header-separator" aria-hidden="true" />
        <span className={`header-scan-state ${state}`}>{state === 'scanning' ? '검사 진행 중' : scan ? statusLabels[scan.scan_status] : requestStateLabels[state] ?? '검사 대기'}</span>
      </div>
    </header>
    <main id="main-content" className="dashboard-main">
      <div className="workspace-title"><div><p className="eyebrow">SECURITY REVIEW / LOCAL</p><h1>보안 분석 워크스페이스</h1></div><p>등록된 프로젝트의 검사 결과와 근거를 살펴보세요.</p></div>
      <QuickStart />
      <section className="scan-toolbar panel" aria-labelledby="scan-config-title">
        <div className="toolbar-heading"><span className="toolbar-icon" aria-hidden="true"><Icon name="sliders"/></span><div><p className="eyebrow">SCAN CONFIGURATION</p><h2 id="scan-config-title">검사 설정</h2></div></div>
        <form onSubmit={runScan} className="toolbar-form">
          <label>검사 대상<select value={targetId} onChange={(e) => setTargetId(e.target.value)} disabled={!options || state === 'scanning'} required>{options?.targets.map((target) => <option key={target.id} value={target.id}>{target.label} ({target.id})</option>)}</select><small>검사 대상이며, 서버에 미리 등록된 프로젝트만 선택할 수 있습니다.</small></label>
          <label>검사 규칙 모음<select value={profileId} onChange={(e) => setProfileId(e.target.value)} disabled={!options || state === 'scanning'} required>{options?.rule_profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.experimental ? 'Experimental · ' : ''}{profile.label}</option>)}</select><small>{selectedProfile?.experimental ? '실험 규칙이며 일반적인 정확도가 충분히 검증됐다는 뜻은 아닙니다.' : '어떤 보안 문제를 찾을지 정하는 검사 규칙 묶음입니다.'}</small></label>
          <label className="token-field">로컬 API 토큰<div className="token-control"><input aria-label="로컬 API 토큰" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} placeholder="서버에 설정한 토큰" aria-describedby="token-help token-security-help" disabled={state === 'scanning'} /><button type="button" className="button clear-token" onClick={clearToken} disabled={!token || state === 'scanning'} aria-label="화면의 API 토큰 지우기">지우기</button></div><small id="token-help">대시보드와 검사 서버가 서로 확인하는 비밀값입니다.</small><details className="token-security-help"><summary>토큰 보호 안내</summary><p id="token-security-help">서버 실행 시 설정한 값과 같은 토큰을 입력하세요. GitHub에 커밋하거나 다른 사람과 공유하지 마세요. 브라우저를 새로고침하면 입력값이 사라집니다. 지우기 버튼은 화면의 입력값만 제거하며 서버 설정은 바꾸지 않습니다.</p></details></label>
          <button className="button primary run-button" type="submit" disabled={!options || !token || !targetId || !profileId || state === 'scanning'}>{state === 'scanning' ? <><span className="spinner" aria-hidden="true" /> 검사 중</> : <><Icon name="play"/> 검사 실행</>}</button>
        </form>
      </section>
      {bootstrapError && <div className="alert error" role="alert">{bootstrapError}</div>}
      <div className="help-strip"><details className="help-disclosure"><summary><Icon name="book"/> 보안 용어 도움말</summary><SecurityGlossary expanded /></details><p className="toolbar-help">토큰은 이 브라우저 메모리에만 보관되며 인증 헤더로 전송됩니다.</p></div>
      <div className="live-message sr-only" role="status" aria-live="polite" aria-atomic="true">{message}</div>
      {scan && <>
        {scanContext && <section className="scan-context panel" aria-label="이 결과를 생성한 검사 설정"><div className="context-copy"><p className="eyebrow">RESULT CONTEXT</p><h2>검사 정보</h2><p><strong>{scanContext.targetLabel}</strong> <code>{scanContext.targetId}</code><span className="context-divider">/</span><strong>{scanContext.experimental ? '실험 · ' : ''}{scanContext.ruleProfileLabel}</strong> <code>{scanContext.ruleProfileId}</code></p><small>결과 수신: {new Date(scanContext.receivedAt).toLocaleString()}</small></div><div className="context-actions"><button type="button" className="button secondary" aria-label="현재 검사 결과 내보내기" onClick={exportResults}><Icon name="download"/> 결과 내보내기</button><button type="button" className="button tertiary" aria-label="결과 지우기" onClick={clearResults}>결과 지우기</button></div><p className="export-note">현재 응답의 최대 50건만 내보냅니다. 파일을 공유하기 전에 내용을 확인하세요.</p>{exportMessage && <p className="export-feedback" role="status">{exportMessage}</p>}</section>}
        {contextChanged && scanContext && <div className="alert warning" role="alert">현재 화면의 결과는 이전 검사 설정({scanContext.targetLabel} · {scanContext.experimental ? '실험 · ' : ''}{scanContext.ruleProfileLabel})에서 생성됐습니다. 현재 선택한 설정({options?.targets.find((target) => target.id === targetId)?.label ?? '알 수 없는 대상'} · {selectedProfile?.experimental ? 'Experimental · ' : ''}{selectedProfile?.label ?? '알 수 없는 규칙'})의 결과는 아직 없습니다. 확인하려면 새 검사를 실행하세요.</div>}
        <section className={`scan-banner ${scan.scan_status}`} aria-labelledby="scan-result-title"><div className="scan-state-copy"><p className="eyebrow">검사 상태 {scan.semgrep_version ? `· Semgrep ${scan.semgrep_version}` : '· 버전 확인 불가'}</p><h2 id="scan-result-title">{statusLabels[scan.scan_status] ?? '알 수 없는 검사 상태'}</h2></div><span className={`state-pill ${scan.scan_status}`}>{scan.completed ? '완료' : scan.scan_status === 'partial' ? '일부만 완료' : '완료되지 않음'}</span></section>
        <ScanStatusGuidance scan={scan} />
        <section className="overview-grid" aria-label="검사 개요"><Metric label="검토 후보" value={scan.finding_count} note="취약점 확정 수가 아닙니다"/><Metric label="표시된 결과" value={scan.displayed_finding_count} note="현재 응답에 포함"/><Metric label="생략된 결과" value={scan.omitted_finding_count} note="개별 상태 미확인"/><div className="panel severity-card"><div className="severity-heading"><Icon name="pulse"/><h3>심각도 분포</h3></div><div className="severity-counts">{severityOrder.map((severity) => <span key={severity} className={`severity-count ${severity}`}><i className={`severity-dot ${severity}`} aria-hidden="true"/><span>{severityLabels[severity]}</span><b>{scan.severity_counts[severity]}</b></span>)}</div><small>Semgrep의 분류입니다. 실제 악용 가능성을 확정하지 않습니다.</small></div></section>
        <section className="findings-section" aria-labelledby="findings-heading">
          <div className="results-heading"><div className="results-title"><p className="eyebrow">FINDING REVIEW</p><h2 id="findings-heading">발견 항목 <span className="count-chip">{scan.finding_count}</span></h2><p>이 검사 응답에 포함된 최대 50건을 표시합니다.</p></div><div className="filter-row"><label className="search-field"><span className="sr-only">파일 경로, 규칙 이름 또는 ID 검색</span><Icon name="search"/><input aria-label="파일 경로, 규칙 이름 또는 ID 검색" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="경로·규칙 검색" /></label><label>심각도<select aria-label="심각도" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}><option value="all">모두</option>{severityOrder.map((x) => <option key={x} value={x}>{severityLabels[x]}</option>)}</select></label><label>유형<select aria-label="유형" value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}><option value="all">모두</option>{Object.entries(kindLabels).map(([key,value]) => <option key={key} value={key}>{value}</option>)}</select></label><label>검증 상태<select aria-label="검증 상태" value={verificationFilter} onChange={(e) => setVerificationFilter(e.target.value)}><option value="all">모두</option><option value="unverified">미검증</option></select></label></div></div>
          {scan.finding_count === 0 ? <div className="empty-state panel"><span className="empty-icon" aria-hidden="true"><Icon name="check"/></span><div><h3>보고된 발견 항목이 없습니다</h3><p>이번 검사에서 후보가 나오지 않았다는 뜻입니다. 프로젝트가 안전하다고 확인된 것은 아닙니다.</p></div></div> : <div className="results-layout"><section className="finding-list panel" aria-label="Finding 목록" tabIndex={0}><div className="list-caption"><span>목록</span><span>{visibleFindings.length} / {scan.displayed_finding_count} 표시</span></div>{visibleFindings.length === 0 ? <p className="no-filter-results">검색 또는 필터와 일치하는 결과가 없습니다.</p> : visibleFindings.map((finding) => <FindingRow key={finding.finding_id} finding={finding} selected={selected?.finding_id === finding.finding_id} onSelect={() => setSelectedId(finding.finding_id)} />)}</section>
            <section className="detail-panel panel" aria-label="선택한 Finding 상세" tabIndex={0}>{selected ? <FindingDetail finding={selected}/> : <div className="select-prompt"><span aria-hidden="true"><Icon name="cursor"/></span><p>왼쪽 목록에서 항목을 선택하면 근거와 검토할 내용을 볼 수 있습니다.</p></div>}</section></div>}
        </section>
      </>}
      {!scan && <section className="welcome panel"><span className="welcome-icon" aria-hidden="true"><Icon name="radar"/></span><div><p className="eyebrow">EVIDENCE-FIRST REVIEW</p><h2>검사 결과를 이곳에서 확인합니다</h2><p>등록된 프로젝트와 규칙을 선택하고 로컬 API 토큰을 입력한 뒤 검사를 시작하세요. 결과에 코드 원문은 포함되지 않습니다.</p></div><div className="welcome-points"><span><b>01</b> 탐지 근거</span><span><b>02</b> 확인되지 않은 내용</span><span><b>03</b> 다음 검토 작업</span></div></section>}
      <footer><span>로컬 분석 · 발견 항목은 취약점 미확인 상태</span><span>정상 완료 또는 0건은 안전성 보증이 아닙니다.</span></footer>
    </main>
  </div>;
}

function Icon({name}:{name:'sliders'|'play'|'book'|'download'|'pulse'|'search'|'check'|'cursor'|'radar'}) {
  const paths:Record<string,React.ReactNode>={
    sliders:<><path d="M4 7h8m4 0h4M4 17h4m4 0h8"/><circle cx="14" cy="7" r="2"/><circle cx="10" cy="17" r="2"/></>,play:<path d="m8 5 11 7-11 7z"/>,
    book:<><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v17H6.5A2.5 2.5 0 0 0 4 22z"/><path d="M4 5.5v14A2.5 2.5 0 0 1 6.5 17H20"/></>,
    download:<><path d="M12 3v12m0 0 4-4m-4 4-4-4"/><path d="M5 17v4h14v-4"/></>,pulse:<><path d="M3 12h4l3-8 4 16 3-8h4"/><circle cx="12" cy="12" r="9"/></>,
    search:<><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></>,check:<path d="m5 12 4 4L19 6"/>,cursor:<path d="m5 3 14 9-7 1-3 7z"/>,
    radar:<><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="m12 12 6-6"/><circle cx="12" cy="12" r="1"/></>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
function Metric({label,value,note}:{label:string;value:number;note:string}) { return <div className="panel metric"><span className="metric-label">{label}</span><strong>{value.toLocaleString('ko-KR')}</strong><small>{note}</small></div>; }
function FindingRow({finding,selected,onSelect}:{finding:ApiFinding;selected:boolean;onSelect:()=>void}) { return <button type="button" className={`finding-row ${selected?'selected':''}`} onClick={onSelect} aria-pressed={selected} aria-label={`${ruleName(finding.rule_id)} (${finding.rule_id}), ${severityLabels[finding.severity]}, ${finding.file_path ?? '위치 확인 불가'}${finding.line_number ? ` ${finding.line_number}행` : ''}, 취약점 여부 미확인`}><span className={`severity-rail ${finding.severity}`} aria-hidden="true"/><span className="row-main"><span className="row-topline"><span className={`severity-label ${finding.severity}`}>{severityLabels[finding.severity]}</span><span className="row-kind">{kindLabels[finding.finding_kind]}</span><span className="unverified-badge">미확인</span></span><strong>{ruleName(finding.rule_id)}</strong><small className="row-location">{finding.file_path ?? '위치 확인 불가'}{finding.line_number ? `:${finding.line_number}` : ''}</small><code className="row-rule-id">{finding.rule_id}</code></span><span className={`validation-icon ${finding.evidence_validation_status}`} title={`근거 검증 ${finding.evidence_validation_status}`} aria-label={`근거 연결 ${finding.evidence_validation_status === 'validated' ? '확인됨' : '확인 불가'}`}>{finding.evidence_validation_status === 'validated' ? '✓' : '!'}</span></button>; }
function FindingDetail({finding}:{finding:ApiFinding}) {
  return <article>
    <div className="detail-top"><div><p className="eyebrow">발견 항목 요약</p><h2>{ruleName(finding.rule_id)}</h2></div><span className={`severity-label ${finding.severity}`}>심각도: {severityLabels[finding.severity]}</span></div>
    <div className="detail-badges"><span>{kindLabels[finding.finding_kind]}</span><span className="unverified-badge">미검증 후보</span></div>
    <div className="detail-location"><span>확인할 파일과 위치</span><strong>{finding.file_path ?? '파일 경로를 확인할 수 없습니다'}{finding.line_number ? `:${finding.line_number}` : ''}</strong><small>이 위치는 규칙이 보고한 매치입니다. 실제 입력 위치나 위험한 함수의 인자 위치와 같다고 확인된 것은 아닙니다.</small></div>
    {finding.evidence_validation_status !== 'validated' && <div className="alert warning" role="note">근거 연결을 검증하지 못해 지원된 근거는 표시하지 않습니다. 자세한 상태와 코드는 기술 상세에서 확인할 수 있습니다.</div>}
    <section className="analyst-tasks"><h3>먼저 확인할 내용</h3><p>아래는 검토 제안입니다. 아직 완료된 확인이 아닙니다.</p><ol>{taskText[finding.finding_kind].map((task) => <li key={task}>{task}</li>)}</ol></section>
    <div className="basic-evidence-limit" role="note"><strong>중요한 제한</strong><p>이 결과는 검토 후보이며 실제 취약점으로 확정되지 않았습니다. Source/Sink 위치와 전체 데이터 전달 경로는 확인되지 않았을 수 있습니다.</p></div>
    <details className="technical-details">
      <summary>기술 근거와 제한 자세히 보기</summary>
      <div className="technical-content">
        <dl className="finding-technical-meta"><div><dt>규칙 ID</dt><dd><code>{finding.rule_id}</code></dd></div><div><dt>Finding ID</dt><dd><code>{finding.finding_id}</code></dd></div><div><dt>분석 유형</dt><dd><code>{finding.finding_kind}</code></dd></div><div><dt>근거 연결 검증</dt><dd><code>{finding.evidence_validation_status}</code></dd></div><div><dt>취약점 상태</dt><dd><code>{finding.verification_status}</code></dd></div></dl>
        {finding.evidence_validation_status !== 'validated' && <div className="alert warning" role="note">근거 검증이 통과하지 않았습니다. 지원된 주장은 표시하지 않습니다.{finding.validation_error_code ? ` (${finding.validation_error_code})` : ''}</div>}
        {finding.evidence_validation_status === 'validated' && <section className="claim-section supported"><h3><span aria-hidden="true">✓</span> 확인된 구조적 근거 <small>{finding.supported_claims.length}</small></h3>{finding.supported_claims.length ? <ul>{finding.supported_claims.map((claim) => <li key={claim}><strong>{claimLabels[claim]}</strong><code>{claim}</code></li>)}</ul> : <p>지원된 주장이 없습니다.</p>}</section>}
        <section className="claim-section restricted"><h3><span aria-hidden="true">!</span> 확인되지 않았거나 지원되지 않는 내용 <small>{finding.restricted_claims.length}</small></h3>{finding.restricted_claims.length ? <ul>{finding.restricted_claims.map((claim) => <li key={claim.claim_type}><div><strong>{claimLabels[claim.claim_type]}</strong><span className="decision">{decisionLabels[claim.decision] ?? '확인 불가'}</span></div><code>{claim.claim_type} · {claim.decision}</code>{claim.reason_codes.map((reason) => <p className="reason" key={reason}>{reasonLabels[reason] ?? '추가 검토가 필요합니다.'}</p>)}</li>)}</ul> : <p>제한된 주장이 없습니다.</p>}</section>
        <p className="detail-footnote">근거 검증 성공은 구조적 연결을 확인한 것이며 Finding은 계속 미검증 상태입니다.</p>
      </div>
    </details>
  </article>;
}
