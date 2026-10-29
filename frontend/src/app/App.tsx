import { useEffect, useMemo, useState } from 'react';
import { api, ApiError } from '../api/client';
import type { ApiFinding, ClaimType, FindingKind, Options, ScanResponse, Severity } from '../api/types';

type RequestState = 'ready' | 'scanning' | 'completed' | 'partial' | 'failed' | 'unauthorized' | 'scan_already_running' | 'connection_error';
const severityOrder: Severity[] = ['critical','high','medium','low','info'];
const severityLabels: Record<Severity,string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const kindLabels: Record<FindingKind,string> = { taint: 'Taint 규칙', pattern: '일반 패턴', unclassified: '분류되지 않음' };
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
  const [selectedId, setSelectedId] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const [verificationFilter, setVerificationFilter] = useState('all');

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
    (verificationFilter === 'all' || finding.verification_status === verificationFilter)), [scan, severityFilter, kindFilter, verificationFilter]);
  const selected = visibleFindings.find((finding) => finding.finding_id === selectedId) ?? visibleFindings[0];

  async function runScan(event: React.FormEvent) {
    event.preventDefault();
    if (!token || !targetId || !profileId || state === 'scanning') return;
    setState('scanning'); setMessage('검사 진행 중입니다. 실제 진행률 정보는 제공되지 않습니다.'); setScan(null); setSelectedId('');
    try {
      const result = await api.scan(token, targetId, profileId);
      setScan(result); setState(result.scan_status === 'completed' ? 'completed' : result.scan_status === 'partial' ? 'partial' : 'failed');
      setMessage(result.scan_status === 'completed' ? 'Semgrep 검사가 정상 완료됐습니다. 결과는 취약점 확정이나 코드 안전성 증명이 아닙니다.' : result.scan_status === 'partial' ? '검사가 일부만 완료됐습니다. 누락된 영역이 있을 수 있습니다.' : `검사 응답은 수신했지만 Semgrep 상태는 ${statusLabels[result.scan_status] ?? '알 수 없음'}입니다.`);
    } catch (error) { const result = safeError(error); setState(result.state); setMessage(result.message); }
  }
  function clearToken() { setToken(''); setState('ready'); setMessage('토큰을 지웠습니다. 토큰은 이 페이지 메모리에만 보관됩니다.'); }

  const selectedProfile = options?.rule_profiles.find((item) => item.id === profileId);
  return <div className="app-shell">
    <header className="topbar"><div className="brand-mark" aria-hidden="true">AC</div><div className="brand-copy"><h1>AI Code Security Analyzer</h1><p>Local Analysis Dashboard</p></div><div className="header-status"><span className={`status-dot ${health}`} aria-hidden="true" /> API {health === 'connected' ? '연결됨' : health === 'checking' ? '확인 중' : '연결 안 됨'}<span className="header-divider" />{state === 'scanning' ? '검사 진행 중' : scan ? statusLabels[scan.scan_status] : requestStateLabels[state] ?? '요청 실패'}</div></header>
    <main>
      <section className="intro"><div><p className="eyebrow">LOCAL · STATIC ANALYSIS</p><h2>검토할 프로젝트를 검사하세요</h2><p>분석 후보를 살펴보고, 확인된 근거와 제한 사항을 함께 검토합니다.</p></div><aside className="notice"><strong>결과 해석</strong><span>Finding은 검토 후보입니다. 심각도나 근거 검증 상태가 취약점 확정을 뜻하지 않습니다.</span></aside></section>
      {bootstrapError && <div className="alert error" role="alert">{bootstrapError}</div>}
      <section className="config-panel panel" aria-labelledby="scan-config-title"><div className="section-heading"><div><p className="eyebrow">SCAN SETUP</p><h2 id="scan-config-title">검사 설정</h2></div><span className="step-tag">01 · CONFIGURE</span></div>
        <form onSubmit={runScan}>
          <div className="form-grid">
            <label>검사 대상<select value={targetId} onChange={(e) => setTargetId(e.target.value)} disabled={!options || state === 'scanning'} required>{options?.targets.map((target) => <option key={target.id} value={target.id}>{target.label}</option>)}</select><small>서버에 허용된 대상만 선택할 수 있습니다.</small></label>
            <label>규칙 프로필<select value={profileId} onChange={(e) => setProfileId(e.target.value)} disabled={!options || state === 'scanning'} required>{options?.rule_profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.experimental ? 'Experimental · ' : ''}{profile.label}</option>)}</select><small>{selectedProfile?.experimental ? '실험 규칙입니다. 결과 범위와 한계를 고려해 검토하세요.' : '기준 보안 규칙 프로필입니다.'}</small></label>
            <label className="token-field">로컬 API 토큰<div className="token-control"><input aria-label="로컬 API 토큰" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} placeholder="서버 설정 토큰을 입력하세요" aria-describedby="token-help" disabled={state === 'scanning'} /><button type="button" className="button secondary clear-token" onClick={clearToken} disabled={!token || state === 'scanning'}>지우기</button></div><small id="token-help">요청 헤더로만 전송되며 브라우저 저장소에는 저장되지 않습니다.</small></label>
          </div>
          <div className="form-actions"><p>검사는 동기 요청입니다. 진행률과 취소 기능은 제공되지 않습니다.</p><button className="button primary run-button" type="submit" disabled={!options || !token || !targetId || !profileId || state === 'scanning'}>{state === 'scanning' ? <><span className="spinner" aria-hidden="true" /> 검사 중</> : '검사 실행'}</button></div>
        </form>
      </section>
      <div className="live-message" role="status" aria-live="polite" aria-atomic="true">{message}</div>
      {scan && <>
        <section className={`scan-banner ${scan.scan_status}`} aria-labelledby="scan-result-title"><div><p className="eyebrow">SCAN RESULT · {scan.semgrep_version ? `SEMGREP ${scan.semgrep_version}` : 'VERSION UNKNOWN'}</p><h2 id="scan-result-title">{statusLabels[scan.scan_status] ?? '알 수 없는 검사 상태'}</h2><p>{scan.scan_status === 'completed' ? '검사가 완료됐습니다. 탐지 결과가 0건이어도 코드가 안전하다는 뜻은 아닙니다.' : scan.scan_status === 'partial' ? '일부 경로 또는 규칙이 누락됐을 수 있습니다. 전체 검사가 완료된 것으로 해석하지 마세요.' : '분석이 실패했습니다. 결과를 안전성 판단이나 취약점 부재 증명으로 사용할 수 없습니다.'}</p></div><span className={`state-pill ${scan.scan_status}`}>{scan.completed ? '완료' : scan.scan_status === 'partial' ? '부분 완료' : '실패'}</span></section>
        <section className="overview-grid" aria-label="검사 개요"><Metric label="검토 후보" value={scan.finding_count} note="취약점 확정 수가 아닙니다"/><Metric label="표시된 결과" value={scan.displayed_finding_count} note="현재 응답에 포함됨"/><Metric label="생략된 결과" value={scan.omitted_finding_count} note="개별 검증 상태 미확인"/><div className="panel severity-card"><h3>심각도 분류</h3><div className="severity-counts">{severityOrder.map((severity) => <span key={severity}><i className={`severity-dot ${severity}`} aria-hidden="true" />{severityLabels[severity]} <b>{scan.severity_counts[severity]}</b></span>)}</div><small>Semgrep의 분류이며 실제 악용 가능성 판정이 아닙니다.</small></div></section>
        {(scan.limitations.length > 0 || scan.issues.length > 0) && <section className="limitations panel"><h3>검사 제한 및 안내</h3><div>{scan.limitations.map((item) => <span className="code-chip" key={item}>{item}</span>)}{scan.issues.map((item) => <span className="code-chip" key={item}>{item}</span>)}</div></section>}
        <div className="results-heading"><div><p className="eyebrow">FINDING REVIEW</p><h2>검토 대상 <span>{scan.finding_count}</span></h2><p>필터는 이 응답에 표시된 최대 50건에만 적용됩니다.</p></div><div className="filter-row"><label>심각도<select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}><option value="all">전체</option>{severityOrder.map((x) => <option key={x} value={x}>{severityLabels[x]}</option>)}</select></label><label>유형<select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}><option value="all">전체</option>{Object.entries(kindLabels).map(([key,value]) => <option key={key} value={key}>{value}</option>)}</select></label><label>검증 상태<select value={verificationFilter} onChange={(e) => setVerificationFilter(e.target.value)}><option value="all">전체</option><option value="unverified">미검증</option></select></label></div></div>
        {scan.finding_count === 0 ? <div className="empty-state panel"><div className="empty-icon" aria-hidden="true">✓</div><h3>보고된 Finding이 없습니다</h3><p>탐지 0건은 대상 코드가 안전하다는 증명이 아닙니다. 규칙 범위와 검사 제한을 함께 확인하세요.</p></div> : <div className="results-layout"><section className="finding-list panel" aria-label="Finding 목록"><div className="list-caption">{visibleFindings.length}건 표시 · 이 검사 응답 기준</div>{visibleFindings.length === 0 ? <p className="no-filter-results">선택한 조건에 맞는 표시 결과가 없습니다.</p> : visibleFindings.map((finding) => <FindingRow key={finding.finding_id} finding={finding} selected={selected?.finding_id === finding.finding_id} onSelect={() => setSelectedId(finding.finding_id)} />)}</section>
          <section className="detail-panel panel" aria-label="선택한 Finding 상세">{selected ? <FindingDetail finding={selected}/> : <div className="select-prompt"><span aria-hidden="true">←</span><p>목록에서 Finding을 선택해 근거와 검토 항목을 확인하세요.</p></div>}</section></div>}
      </>}
      {!scan && <section className="welcome panel"><div className="welcome-icon" aria-hidden="true">⌕</div><div><p className="eyebrow">EVIDENCE-FIRST REVIEW</p><h2>검사 결과가 여기에 표시됩니다</h2><p>허용된 프로젝트와 규칙을 선택하고 토큰을 입력한 뒤 검사를 실행하세요. 코드 원문은 대시보드 응답에 포함되지 않습니다.</p></div><div className="welcome-points"><span><b>01</b> 구조화된 근거</span><span><b>02</b> 제한 사항 분리</span><span><b>03</b> 수동 검토 안내</span></div></section>}
      <footer><span>로컬 분석 결과 · Finding 상태는 미검증</span><span>0건 탐지 또는 정상 완료는 안전성 보증이 아닙니다.</span></footer>
    </main>
  </div>;
}

function Metric({label,value,note}:{label:string;value:number;note:string}) { return <div className="panel metric"><span>{label}</span><strong>{value.toLocaleString('ko-KR')}</strong><small>{note}</small></div>; }
function FindingRow({finding,selected,onSelect}:{finding:ApiFinding;selected:boolean;onSelect:()=>void}) { return <button type="button" className={`finding-row ${selected?'selected':''}`} onClick={onSelect} aria-pressed={selected}><span className={`severity-rail ${finding.severity}`} aria-hidden="true"/><span className="row-main"><strong>{finding.rule_id}</strong><span className="row-meta"><span className={`severity-label ${finding.severity}`}>{severityLabels[finding.severity]}</span><span>{kindLabels[finding.finding_kind]}</span><span>{finding.verification_status}</span></span><small>{finding.file_path ?? '위치 확인 불가'}{finding.line_number ? `:${finding.line_number}` : ''}</small></span><span className={`validation-icon ${finding.evidence_validation_status}`} title={`근거 검증 ${finding.evidence_validation_status}`} aria-label={`근거 검증 ${finding.evidence_validation_status}`}>{finding.evidence_validation_status === 'validated' ? '✓' : '!'}</span></button>; }
function FindingDetail({finding}:{finding:ApiFinding}) { return <article><div className="detail-top"><div><p className="eyebrow">FINDING DETAIL</p><h2>{finding.rule_id}</h2></div><span className={`severity-label ${finding.severity}`}>{severityLabels[finding.severity]}</span></div><p className="finding-id">{finding.finding_id}</p><div className="detail-badges"><span>{kindLabels[finding.finding_kind]}</span><span>상태: 미검증</span><span>근거 구조: {finding.evidence_validation_status}</span></div><div className="detail-location"><span>관찰된 매치 위치</span><strong>{finding.file_path ?? '경로 확인 불가'}{finding.line_number ? `:${finding.line_number}` : ''}</strong><small>표시 위치는 Semgrep 매치 위치이며 별도의 Sink 인자 위치를 뜻하지 않습니다.</small></div>
    {finding.evidence_validation_status !== 'validated' && <div className="alert warning" role="note">근거 검증이 통과하지 않았습니다. 지원된 주장은 표시하지 않습니다.{finding.validation_error_code ? ` (${finding.validation_error_code})` : ''}</div>}
    {finding.evidence_validation_status === 'validated' && <section className="claim-section supported"><h3><span aria-hidden="true">✓</span> 확인된 구조적 근거 <small>{finding.supported_claims.length}</small></h3>{finding.supported_claims.length ? <ul>{finding.supported_claims.map((claim) => <li key={claim}><strong>{claimLabels[claim]}</strong><code>{claim}</code></li>)}</ul> : <p>지원된 주장이 없습니다.</p>}</section>}
    <section className="claim-section restricted"><h3><span aria-hidden="true">!</span> 확인되지 않았거나 지원되지 않는 내용 <small>{finding.restricted_claims.length}</small></h3>{finding.restricted_claims.length ? <ul>{finding.restricted_claims.map((claim) => <li key={claim.claim_type}><div><strong>{claimLabels[claim.claim_type]}</strong><span className="decision">{decisionLabels[claim.decision] ?? '확인 불가'}</span></div><code>{claim.claim_type} · {claim.decision}</code>{claim.reason_codes.map((reason) => <p className="reason" key={reason}>{reasonLabels[reason] ?? '추가 검토가 필요합니다.'}</p>)}</li>)}</ul> : <p>제한된 주장이 없습니다.</p>}</section>
    <section className="analyst-tasks"><h3>분석가 추가 검토 항목</h3><p>아래 항목은 확인을 위한 제안이며 완료된 검증 결과가 아닙니다.</p><ol>{taskText[finding.finding_kind].map((task) => <li key={task}>{task}</li>)}</ol></section><p className="detail-footnote">근거 검증 성공은 구조적 연결을 확인한 것이며 Finding은 계속 미검증 상태입니다.</p>
  </article>; }
