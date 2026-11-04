import { useEffect, useMemo, useRef, useState } from 'react';
import { api, ApiError } from '../api/client';
import { investigationApi, type InvestigationEvaluation, type InvestigationCategory } from '../api/investigation';
import type { ApiFinding, ClaimType, FindingKind, Options, ScanResponse, Severity } from '../api/types';
import { createReviewMarkdown, downloadReviewMarkdown, type ScanContext } from '../features/scans/markdownExport';
import { compareScanSnapshots, type ComparisonBlockReason, type ComparisonGroups, type ScanSnapshot } from '../features/scans/compare';
import { createComparisonMarkdown, downloadComparisonMarkdown } from '../features/scans/comparisonMarkdownExport';
import { countAnalystReviewStatuses, emptyAnalystReviewState, filterFindingsByAnalystStatus, getAnalystReviewEntry, hasAnalystReviewWork, setAnalystReviewNote, setAnalystReviewStatus, type AnalystReviewFilter, type AnalystReviewState, type AnalystReviewStatus } from '../features/scans/analystReview';
import { createAnalystReviewMarkdown, downloadAnalystReviewMarkdown } from '../features/scans/analystReviewMarkdownExport';
import { ANALYST_REVIEW_BACKUP_FILENAME, createAnalystReviewBackup, downloadAnalystReviewBackup, MAX_ANALYST_REVIEW_BACKUP_BYTES, parseAnalystReviewBackup, validateBackupForRestore, type AnalystReviewBackup, type RestoreBlockReason } from '../features/scans/analystReviewBackup';
import { createScanTriage, type FindingTriage } from '../features/scans/findingTriage';
import { getFindingReviewGuidance } from '../features/scans/reviewGuidance';
import { createRescanFollowup, type RescanFollowup } from '../features/scans/rescanFollowup';
import { createSarifReport, downloadSarifReport, SARIF_FILENAME } from '../features/scans/sarifExport';
import { createCodeScanningPreflight, type CodeScanningPreflight } from '../features/scans/codeScanningPreflight';
import { validateInvestigationContext, validateInvestigationRuns, type EvidenceBackedScan } from '../features/scans/investigationWorkflow';
import { investigationAssessmentLabels, investigationErrorMessage, investigationLimitationLabels, investigationPathLabels } from '../features/scans/investigationMessages';
import { QuickStart, ScanStatusGuidance, SecurityGlossary, ServerAdminSettings } from './BeginnerGuidance';

type RequestState = 'ready' | 'scanning' | 'completed' | 'partial' | 'failed' | 'unauthorized' | 'scan_already_running' | 'connection_error';
type WorkspaceView = 'start' | 'results' | 'guide';
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
const statusLabels: Record<string,string> = { completed:'정상 완료', partial:'부분 검사', execution_failed:'실행 실패', not_installed:'Semgrep 미설치', invalid_json:'결과 형식 오류', timed_out:'시간 초과', output_limit_exceeded:'출력 제한 초과' };
const analystReviewLabels: Record<AnalystReviewStatus,string> = { pending: '검토 대기', needs_followup: '추가 확인 필요', reviewed: '검토 완료' };
const restoreReasonLabels: Record<RestoreBlockReason, string> = {
  current_scan_not_completed: '현재 검사가 정상 완료되지 않았습니다.', current_findings_omitted: '현재 결과에 생략된 Finding이 있습니다.',
  backup_scan_not_completed: '백업 원본 검사가 정상 완료되지 않았습니다.', backup_findings_omitted: '백업에 생략된 Finding이 있습니다.',
  target_mismatch: '검사 대상 ID가 다릅니다.', rule_profile_mismatch: '규칙 프로필 ID가 다릅니다.', experimental_mismatch: 'Experimental 설정이 다릅니다.',
  semgrep_version_unavailable: '양쪽 Semgrep 버전을 확인할 수 없습니다.', semgrep_version_mismatch: 'Semgrep 버전이 다릅니다.',
  finding_set_mismatch: 'Finding ID 구성이 다릅니다.', finding_metadata_mismatch: 'Finding의 규칙·위치·심각도·유형 정보가 다릅니다.',
  scan_count_inconsistent: '검사 결과 개수가 일치하지 않습니다.', current_context_mismatch: '현재 검사 문맥이 결과와 일치하지 않습니다.',
};
const errorLabels: Record<string,string> = {
  unauthorized:'토큰을 확인하세요. 인증되지 않아 검사를 실행하지 않았습니다.', origin_not_allowed:'브라우저 출처가 서버 허용 목록에 없습니다. 서버의 Origin 설정을 확인하세요.',
  scan_already_running:'이미 검사가 진행 중입니다. 완료 후 다시 시도하세요.', target_not_allowed:'허용되지 않은 프로젝트입니다.', rule_profile_not_allowed:'허용되지 않은 규칙 프로필입니다.',
  response_limit_exceeded:'응답이 허용 크기를 초과했습니다.', invalid_request:'요청을 확인할 수 없습니다.', internal_error:'서버 내부 오류가 발생했습니다.',
  connection_error:'로컬 API에 연결할 수 없습니다.', invalid_api_response:'서버 응답 형식을 확인할 수 없습니다.', request_failed:'요청이 거부되었습니다.',
};
async function releaseEvidenceHandle(token: string, kind: 'run' | 'investigation', handle: string): Promise<void> {
  try { await investigationApi.release(token, kind, handle); } catch { /* The server's absolute TTL remains the cleanup bound. */ }
}
function safeError(error: unknown): { state: RequestState; message: string } {
  if (!(error instanceof ApiError)) return { state:'failed', message:'요청을 완료하지 못했습니다.' };
  const state: RequestState = error.code === 'connection_error' || error.status === 0 ? 'connection_error' : error.code === 'unauthorized' || error.status === 401 ? 'unauthorized' : error.code === 'scan_already_running' || error.status === 409 ? 'scan_already_running' : 'failed';
  return { state, message: errorLabels[error.code] ?? `요청이 거부되었습니다 (HTTP ${error.status}).` };
}

export function App() {
  const [health, setHealth] = useState<'checking'|'connected'|'offline'>('checking');
  const [connectionAttempt, setConnectionAttempt] = useState(0);
  const [options, setOptions] = useState<Options | null>(null);
  const [bootstrapError, setBootstrapError] = useState('');
  const [token, setToken] = useState('');
  const [targetId, setTargetId] = useState('');
  const [profileId, setProfileId] = useState('');
  const [state, setState] = useState<RequestState>('ready');
  const [message, setMessage] = useState('');
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [scanContext, setScanContext] = useState<ScanContext | null>(null);
  const [baselineSnapshot, setBaselineSnapshot] = useState<ScanSnapshot | null>(null);
  const scanRequestSequence = useRef(0);
  const [investigationMode, setInvestigationMode] = useState(false);
  const [currentEvidence, setCurrentEvidence] = useState<EvidenceBackedScan | null>(null);
  const [baselineEvidence, setBaselineEvidence] = useState<EvidenceBackedScan | null>(null);
  const [investigationHandle, setInvestigationHandle] = useState<string | null>(null);
  const [investigationEvaluation, setInvestigationEvaluation] = useState<InvestigationEvaluation | null>(null);
  const [investigationState, setInvestigationState] = useState<'idle' | 'running' | 'ready' | 'error'>('idle');
  const [investigationMessage, setInvestigationMessage] = useState('');
  const investigationRequestSequence = useRef(0);
  const [exportMessage, setExportMessage] = useState('');
  const [sarifExportMessage, setSarifExportMessage] = useState('');
  const [comparisonExportMessage, setComparisonExportMessage] = useState('');
  const [analystReviewExportMessage, setAnalystReviewExportMessage] = useState('');
  const [includeAnalystNotes, setIncludeAnalystNotes] = useState(false);
  const [includeBackupNotes, setIncludeBackupNotes] = useState(false);
  const [backupMessage, setBackupMessage] = useState('');
  const [backupPreview, setBackupPreview] = useState<{ backup: AnalystReviewBackup; reasons: RestoreBlockReason[]; scan: ScanResponse; context: ScanContext; fileName: string } | null>(null);
  const [backupAppliedIds, setBackupAppliedIds] = useState<ReadonlySet<string>>(() => new Set());
  const [backupSkippedIds, setBackupSkippedIds] = useState<ReadonlySet<string>>(() => new Set());
  const currentScanRef = useRef(scan);
  const currentScanContextRef = useRef(scanContext);
  const currentEvidenceRef = useRef(currentEvidence);
  const baselineEvidenceRef = useRef(baselineEvidence);
  const investigationHandleRef = useRef(investigationHandle);
  const tokenRef = useRef(token);
  currentScanRef.current = scan;
  currentScanContextRef.current = scanContext;
  currentEvidenceRef.current = currentEvidence;
  baselineEvidenceRef.current = baselineEvidence;
  investigationHandleRef.current = investigationHandle;
  tokenRef.current = token;
  const [selectedId, setSelectedId] = useState('');
  const [analystReviews, setAnalystReviews] = useState<AnalystReviewState>(emptyAnalystReviewState);
  const [analystReviewFilter, setAnalystReviewFilter] = useState<AnalystReviewFilter>('all');
  const [analystNoteError, setAnalystNoteError] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const [verificationFilter, setVerificationFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeView, setActiveView] = useState<WorkspaceView>('start');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const mobileMenuButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const sidebar = document.getElementById('workspace-sidebar');
    const navItems = sidebar?.querySelectorAll<HTMLButtonElement>('.nav-item');
    navItems?.[0]?.focus();
    const handleDrawerKeys = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setMobileNavOpen(false); mobileMenuButton.current?.focus(); return; }
      if (event.key !== 'Tab' || !navItems?.length) return;
      const first = navItems[0];
      const last = navItems[navItems.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener('keydown', handleDrawerKeys);
    return () => window.removeEventListener('keydown', handleDrawerKeys);
  }, [mobileNavOpen]);

  useEffect(() => () => {
    scanRequestSequence.current += 1;
    investigationRequestSequence.current += 1;
    const activeToken = tokenRef.current;
    const session = investigationHandleRef.current;
    const runs = new Set([currentEvidenceRef.current?.runHandle, baselineEvidenceRef.current?.runHandle].filter((value): value is string => Boolean(value)));
    if (activeToken && session) void releaseEvidenceHandle(activeToken, 'investigation', session);
    if (activeToken) for (const handle of runs) void releaseEvidenceHandle(activeToken, 'run', handle);
  }, []);

  useEffect(() => {
    let active = true;
    setHealth('checking'); setBootstrapError('');
    if (connectionAttempt > 0) { setOptions(null); setTargetId(''); setProfileId(''); }
    Promise.all([api.health(), api.options()]).then(([_, data]) => {
      if (!active) return;
      setHealth('connected'); setOptions(data);
      setTargetId(data.targets[0]?.id ?? ''); setProfileId(data.rule_profiles[0]?.id ?? '');
    }).catch(() => { if (active) { setHealth('offline'); setBootstrapError('로컬 API에 연결할 수 없습니다. 검사 서버를 실행하고 브라우저 출처 허용 설정을 확인한 뒤 다시 연결하세요.'); } });
    return () => { active = false; };
  }, [connectionAttempt]);

  const baseVisibleFindings = useMemo(() => (scan?.findings ?? []).filter((finding) =>
    (severityFilter === 'all' || finding.severity === severityFilter) &&
    (kindFilter === 'all' || finding.finding_kind === kindFilter) &&
    (verificationFilter === 'all' || finding.verification_status === verificationFilter) &&
    (!searchQuery.trim() || [ruleName(finding.rule_id), finding.rule_id, finding.file_path ?? '', finding.line_number?.toString() ?? ''].some((value) => value.toLocaleLowerCase('ko-KR').includes(searchQuery.trim().toLocaleLowerCase('ko-KR'))))), [scan, severityFilter, kindFilter, verificationFilter, searchQuery]);
  const visibleFindings = useMemo(() => filterFindingsByAnalystStatus(baseVisibleFindings, analystReviews, analystReviewFilter), [baseVisibleFindings, analystReviews, analystReviewFilter]);
  const scanTriage = useMemo(() => scan ? createScanTriage(scan) : null, [scan]);
  const codeScanningPreflight = useMemo(() => {
    if (!scan || !scanContext) return null;
    try { return createCodeScanningPreflight(scan, scanContext, createSarifReport(scanContext, scan)); }
    catch { return null; }
  }, [scan, scanContext]);
  const selected = selectedId
    ? visibleFindings.find((finding) => finding.finding_id === selectedId)
    : visibleFindings[0];
  const currentSnapshot = useMemo(() => scan && scanContext ? { scan, context: scanContext } : null, [scan, scanContext]);
  const comparison = useMemo(() => compareScanSnapshots(baselineSnapshot, currentSnapshot), [baselineSnapshot, currentSnapshot]);
  const rescanFollowup = useMemo(() => createRescanFollowup(
    comparison,
    baselineSnapshot,
    currentSnapshot,
    scanTriage,
  ), [comparison, baselineSnapshot, currentSnapshot, scanTriage]);
  const analystReviewCounts = useMemo(() => countAnalystReviewStatuses(scan?.findings ?? [], analystReviews), [scan, analystReviews]);

  async function dropInvestigationSession(): Promise<void> {
    investigationRequestSequence.current += 1;
    const handle = investigationHandleRef.current;
    investigationHandleRef.current = null;
    setInvestigationHandle(null);
    setInvestigationEvaluation(null);
    setInvestigationState('idle');
    if (handle && tokenRef.current) await releaseEvidenceHandle(tokenRef.current, 'investigation', handle);
  }

  async function releaseInvestigationEvidence(keepRunHandle?: string): Promise<void> {
    const activeToken = tokenRef.current;
    investigationRequestSequence.current += 1;
    const session = investigationHandleRef.current;
    investigationHandleRef.current = null;
    setInvestigationHandle(null); setInvestigationEvaluation(null); setInvestigationState('idle');
    const current = currentEvidenceRef.current;
    const baseline = baselineEvidenceRef.current;
    const handles = new Set([current?.runHandle, baseline?.runHandle]
      .filter((value): value is string => Boolean(value) && value !== keepRunHandle));
    const nextCurrent = keepRunHandle && current?.runHandle === keepRunHandle ? current : null;
    const nextBaseline = keepRunHandle && baseline?.runHandle === keepRunHandle ? baseline : null;
    currentEvidenceRef.current = nextCurrent; baselineEvidenceRef.current = nextBaseline;
    setCurrentEvidence(nextCurrent); setBaselineEvidence(nextBaseline);
    if (activeToken && session) await releaseEvidenceHandle(activeToken, 'investigation', session);
    if (activeToken) for (const handle of handles) await releaseEvidenceHandle(activeToken, 'run', handle);
  }

  function changeInvestigationMode(enabled: boolean) {
    if (enabled === investigationMode) return;
    setInvestigationMode(enabled);
    setInvestigationMessage('');
    if (!enabled) {
      void releaseInvestigationEvidence();
      setInvestigationMessage('조사 모드를 해제했습니다. 보유 중인 서버 증거의 해제를 요청했습니다. 현재 화면의 검사 결과는 유지됩니다.');
    }
  }

  async function runScan(event: React.FormEvent) {
    event.preventDefault();
    if (!token || !targetId || !profileId || state === 'scanning') return;
    const target = options?.targets.find((item) => item.id === targetId);
    const profile = options?.rule_profiles.find((item) => item.id === profileId);
    if (!target || !profile) return;
    if (scan && hasAnalystReviewWork(scan.findings, analystReviews)
      && !window.confirm('현재 검사에 작성한 분석가 검토 상태와 메모가 새 검사 시작 시 사라집니다. 계속하시겠습니까?')) return;
    const requestSequence = ++scanRequestSequence.current;
    investigationRequestSequence.current += 1;
    const runWithEvidence = investigationMode;
    const priorSession = investigationHandleRef.current;
    investigationHandleRef.current = null;
    setInvestigationHandle(null); setInvestigationEvaluation(null); setInvestigationState('idle'); setInvestigationMessage('');
    const priorCurrent = currentEvidenceRef.current;
    const baselineHandle = baselineEvidenceRef.current?.runHandle;
    setCurrentEvidence(null);
    const requestedContext = { targetId: target.id, targetLabel: target.label, ruleProfileId: profile.id, ruleProfileLabel: profile.label, experimental: profile.experimental };
    setState('scanning'); setMessage('검사 진행 중입니다. 실제 진행률 정보는 제공되지 않습니다.'); setScan(null); setScanContext(null); setAnalystReviews(emptyAnalystReviewState); setAnalystReviewFilter('all'); setAnalystNoteError(''); setSelectedId(''); setExportMessage(''); setSarifExportMessage(''); setComparisonExportMessage(''); setAnalystReviewExportMessage(''); setIncludeAnalystNotes(false); setBackupPreview(null); setBackupMessage(''); setIncludeBackupNotes(false); setBackupAppliedIds(new Set()); setBackupSkippedIds(new Set()); resetFilters();
    try {
      if (priorSession) await releaseEvidenceHandle(token, 'investigation', priorSession);
      if (priorCurrent && priorCurrent.runHandle !== baselineHandle) await releaseEvidenceHandle(token, 'run', priorCurrent.runHandle);
      if (requestSequence !== scanRequestSequence.current) return;
      const evidenceResponse = runWithEvidence ? await investigationApi.scan(token, targetId, profileId) : null;
      const result = evidenceResponse?.scan ?? await api.scan(token, targetId, profileId);
      if (requestSequence !== scanRequestSequence.current) {
        if (evidenceResponse) await releaseEvidenceHandle(token, 'run', evidenceResponse.run_handle);
        return;
      }
      const nextContext = { ...requestedContext, scanStatus: result.scan_status, receivedAt: new Date().toISOString() };
      const snapshot: ScanSnapshot = { scan: result, context: nextContext };
      setScan(result); setScanContext(nextContext);
      if (evidenceResponse) setCurrentEvidence({ snapshot, runHandle: evidenceResponse.run_handle });
      setState(result.scan_status === 'completed' ? 'completed' : result.scan_status === 'partial' ? 'partial' : 'failed'); setActiveView('results');
      const scanMessage = result.scan_status === 'completed' ? 'Semgrep 검사가 정상 완료됐습니다. 결과는 취약점 확정이나 코드 안전성 증명이 아닙니다.' : result.scan_status === 'partial' ? '검사가 일부만 완료됐습니다. 누락된 영역이 있을 수 있습니다.' : `검사 응답은 수신했지만 Semgrep 상태는 ${statusLabels[result.scan_status] ?? '알 수 없음'}입니다.`;
      setMessage(scanMessage);
      if (evidenceResponse) setInvestigationMessage('이 검사 응답과 서버 증거 Handle을 함께 보관했습니다. 서버 메모리의 절대 보존 시간은 최대 15분입니다.');
    } catch (error) {
      if (requestSequence !== scanRequestSequence.current) return;
      if (runWithEvidence) {
        const apiError = error instanceof ApiError ? error : new ApiError(500, 'invalid_api_response');
        const mapped = investigationErrorMessage(apiError.status, apiError.code);
        const standard = safeError(error);
        setState(standard.state); setMessage(mapped); setInvestigationMessage(mapped); setInvestigationState('error');
      } else {
        const result = safeError(error); setState(result.state); setMessage(result.message);
      }
    }
  }
  function clearToken() { void releaseInvestigationEvidence(); setToken(''); setState('ready'); setMessage('화면에 입력한 토큰을 지웠습니다. 서버 설정의 토큰은 변경되지 않습니다.'); setInvestigationMessage('토큰이 제거되어 조사 Handle을 사용할 수 없습니다. 해제를 요청했으며 보존 한계는 서버의 15분 TTL입니다.'); }
  function resetFilters() { setSeverityFilter('all'); setKindFilter('all'); setVerificationFilter('all'); setSearchQuery(''); }
  function updateAnalystStatus(findingId: string, nextStatus: AnalystReviewStatus) {
    setSelectedId(findingId);
    const next = setAnalystReviewStatus(analystReviews, scan?.findings ?? [], findingId, nextStatus);
    if (next) { setAnalystReviews(next); setAnalystNoteError(''); }
  }
  function updateAnalystNote(findingId: string, note: string) {
    setSelectedId(findingId);
    const result = setAnalystReviewNote(analystReviews, scan?.findings ?? [], findingId, note);
    if (result.accepted) { setAnalystReviews(result.state); setAnalystNoteError(''); }
    else setAnalystNoteError(result.reason === 'note_too_large' ? '메모는 UTF-8 기준 2 KiB까지 입력할 수 있습니다. 기존 메모는 유지됩니다.' : '현재 검사에 포함된 Finding만 수정할 수 있습니다.');
  }
  function clearResults() {
    if (state === 'scanning') return;
    if (scan && hasAnalystReviewWork(scan.findings, analystReviews)
      && !window.confirm('현재 검사 결과의 분석가 검토 상태와 메모, 비교 기준이 모두 삭제됩니다. 계속하시겠습니까?')) return;
    scanRequestSequence.current += 1;
    void releaseInvestigationEvidence(); setBaselineEvidence(null); setCurrentEvidence(null); setInvestigationMessage('');
    setScan(null); setScanContext(null); setBaselineSnapshot(null); setAnalystReviews(emptyAnalystReviewState); setAnalystReviewFilter('all'); setAnalystNoteError(''); setSelectedId(''); setBackupPreview(null); setBackupMessage(''); setIncludeBackupNotes(false); setBackupAppliedIds(new Set()); setBackupSkippedIds(new Set()); resetFilters(); setExportMessage(''); setSarifExportMessage(''); setComparisonExportMessage(''); setAnalystReviewExportMessage(''); setIncludeAnalystNotes(false); setMessage('화면의 검사 결과와 비교 기준을 지웠습니다. 서버의 검사 취소나 다운로드 파일 삭제는 수행하지 않습니다.');
    if (state !== 'unauthorized' && state !== 'connection_error' && state !== 'scan_already_running') setState('ready');
  }
  function setCurrentAsBaseline() {
    if (!scan || !scanContext || scan.scan_status !== 'completed' || !scan.completed) return;
    const nextEvidence = currentEvidence?.snapshot.scan === scan && currentEvidence.snapshot.context === scanContext ? currentEvidence : null;
    const previousHandle = baselineEvidenceRef.current?.runHandle;
    void (async () => {
      await dropInvestigationSession();
      if (previousHandle && previousHandle !== nextEvidence?.runHandle && previousHandle !== currentEvidenceRef.current?.runHandle && tokenRef.current) await releaseEvidenceHandle(tokenRef.current, 'run', previousHandle);
    })();
    const nextSnapshot = nextEvidence?.snapshot ?? { scan, context: scanContext };
    setBaselineSnapshot(nextSnapshot);
    setBaselineEvidence(nextEvidence);
    setComparisonExportMessage('');
    setMessage(nextEvidence
      ? '현재 검사 결과와 같은 실행에서 발급된 증거를 비교 기준으로 저장했습니다. 같은 프로젝트를 다시 조사 모드로 검사하세요.'
      : '현재 검사 결과를 비교 기준으로 저장했습니다. 이 기준에는 서버 조사 증거가 없으므로 소멸 근거 조사에는 조사 모드에서 새 기준 검사가 필요합니다.');
  }
  function clearBaseline() {
    const oldHandle = baselineEvidenceRef.current?.runHandle;
    const activeHandle = currentEvidenceRef.current?.runHandle;
    void (async () => {
      await dropInvestigationSession();
      if (oldHandle && oldHandle !== activeHandle && tokenRef.current) await releaseEvidenceHandle(tokenRef.current, 'run', oldHandle);
    })();
    setBaselineEvidence(null); setInvestigationMessage('');
    setBaselineSnapshot(null);
    setComparisonExportMessage('');
    setMessage('비교 기준을 해제했습니다. 현재 검사 결과와 분석가 검토 기록은 유지됩니다.');
  }

  async function investigateFindingChanges() {
    if (!token || !baselineSnapshot || !baselineEvidence || !currentEvidence || !scan || currentEvidence.snapshot.scan !== scan
      || baselineEvidence.snapshot !== baselineSnapshot || investigationState === 'running') return;
    const localBinding = validateInvestigationRuns(baselineEvidence, currentEvidence);
    if (!localBinding.valid) {
      setInvestigationState('error'); setInvestigationEvaluation(null);
      setInvestigationMessage(localBinding.reason === 'evidence_missing' ? '두 검사 모두 조사 모드에서 실행해야 서버 증거를 연결할 수 있습니다.' : '검사 실행 문맥이 일치하지 않아 조사를 시작하지 않았습니다.');
      return;
    }
    const requestSequence = ++investigationRequestSequence.current;
    setInvestigationState('running'); setInvestigationMessage('두 검사에서 보관한 서버 증거를 확인하고 있습니다.'); setInvestigationEvaluation(null);
    let session = investigationHandleRef.current;
    try {
      if (!session) {
        const created = await investigationApi.createSession(token, baselineEvidence.runHandle, currentEvidence.runHandle);
        session = created.investigation_handle;
        if (requestSequence !== investigationRequestSequence.current) {
          await releaseEvidenceHandle(token, 'investigation', session);
          return;
        }
        investigationHandleRef.current = session; setInvestigationHandle(session);
      }
      const result = await investigationApi.evaluate(token, session);
      if (requestSequence !== investigationRequestSequence.current) return;
      const resultBinding = validateInvestigationContext(
        baselineEvidence, currentEvidence, result, comparison.comparable ? comparison : undefined,
      );
      if (!resultBinding.valid) {
        void releaseInvestigationEvidence();
        setInvestigationState('error'); setInvestigationEvaluation(null);
        setInvestigationMessage('INVESTIGATION_RESULT_CONTEXT_MISMATCH: 현재 비교 화면과 서버 평가의 Finding 구성이 달라 결과를 표시하지 않았습니다. 새 조사 검사를 실행하세요.');
        return;
      }
      setInvestigationEvaluation(result); setInvestigationState('ready');
      setInvestigationMessage(result.overall_assessment === 'EXPLANATION_SUPPORTED'
        ? '일부 검사 절차에 대한 설명을 뒷받침하는 근거가 있습니다. 코드 수정이나 취약점 해결 여부는 확인되지 않았습니다.'
        : '서버 증거 평가가 완료됐습니다. Finding 미관찰은 취약점 수정이나 해결 완료의 증거가 아닙니다.');
    } catch (error) {
      if (requestSequence !== investigationRequestSequence.current) return;
      const apiError = error instanceof ApiError ? error : new ApiError(500, 'invalid_api_response');
      const mapped = investigationErrorMessage(apiError.status, apiError.code);
      if (apiError.code === 'evidence_unavailable' || apiError.status === 404) {
        void releaseInvestigationEvidence();
      }
      setInvestigationState('error'); setInvestigationEvaluation(null); setInvestigationMessage(mapped);
    }
  }

  function releaseInvestigation() {
    void releaseInvestigationEvidence(); setInvestigationMessage('조사 세션과 Run 증거의 해제를 요청했습니다. 화면의 검사 결과는 유지되지만 다시 조사하려면 두 검사를 새로 실행해야 합니다. 전달 실패 시에도 서버의 최대 15분 TTL이 적용됩니다.');
  }
  function openCurrentFindingFromComparison(findingId: string) {
    if (!scan?.findings.some((finding) => finding.finding_id === findingId)) return;
    resetFilters();
    setAnalystReviewFilter('all');
    setSelectedId(findingId);
    setActiveView('results');
    setMessage('비교 후속 검토에서 현재 Finding으로 이동했습니다. 검색과 필터는 해당 항목을 표시하도록 초기화했으며 검토 상태와 메모는 유지했습니다.');
    window.setTimeout(() => document.querySelector<HTMLElement>('.detail-panel[aria-label="선택한 Finding 상세"]')?.focus(), 0);
  }
  function exportResults() {
    if (!scan || !scanContext) return;
    try { downloadReviewMarkdown(createReviewMarkdown(scanContext, scan)); setExportMessage('현재 API 응답에 포함된 Finding 요약을 다운로드했습니다.'); }
    catch { setExportMessage('요약을 내보낼 수 없습니다. 출력 크기 제한을 확인하세요.'); }
  }
  function exportSarif() {
    if (state === 'scanning' || !scan || !scanContext) return;
    try {
      downloadSarifReport(createSarifReport(scanContext, scan));
      setSarifExportMessage(`SARIF 2.1.0 파일을 다운로드했습니다: ${SARIF_FILENAME}. GitHub 업로드는 수행하지 않았습니다.`);
    } catch (error) {
      setSarifExportMessage(error instanceof Error && error.message === 'sarif_size_limit_exceeded'
        ? 'SARIF 파일이 512 KiB 제한을 초과해 전체 다운로드를 취소했습니다.'
        : 'SARIF 파일을 생성하거나 다운로드하지 못했습니다. 현재 검사 데이터를 확인하세요.');
    }
  }
  function exportComparisonReport() {
    if (state === 'scanning' || !baselineSnapshot || !scan || !scanContext) return;
    try {
      const markdown = createComparisonMarkdown(baselineSnapshot, { scan, context: scanContext });
      downloadComparisonMarkdown(markdown);
      setComparisonExportMessage('두 검사에서 관찰된 비교 보고서를 다운로드했습니다. 공유 전 파일 내용을 확인하세요.');
    } catch (error) {
      setComparisonExportMessage(error instanceof Error && error.message === 'comparison_export_size_limit_exceeded'
        ? '보고서가 512 KiB 제한을 초과해 다운로드하지 않았습니다.'
        : '비교할 수 있는 검사 결과가 아니거나 보고서를 생성하지 못했습니다.');
    }
  }
  function exportAnalystReviewReport() {
    if (state === 'scanning' || !scan || !scanContext) return;
    if (includeAnalystNotes && !window.confirm('분석가 메모에는 내부 코드 정보나 민감정보가 포함될 수 있습니다. 다운로드한 파일은 브라우저 메모리와 달리 디스크에 남으므로 외부 공유 전에 확인하세요. 메모를 포함해 다운로드할까요?')) {
      setAnalystReviewExportMessage('메모 포함을 확인하지 않아 다운로드를 취소했습니다.');
      return;
    }
    try {
      const markdown = createAnalystReviewMarkdown(scanContext, scan, analystReviews, includeAnalystNotes);
      downloadAnalystReviewMarkdown(markdown);
      setAnalystReviewExportMessage(includeAnalystNotes ? '분석가 검토 기록과 선택한 메모를 다운로드했습니다. 파일을 외부 공유하기 전에 내용을 확인하세요.' : '분석가 검토 기록을 다운로드했습니다. 메모는 포함하지 않았습니다.');
    } catch (error) {
      setAnalystReviewExportMessage(error instanceof Error && error.message === 'analyst_review_export_size_limit_exceeded'
        ? '보고서가 512 KiB 제한을 초과해 다운로드하지 않았습니다.'
        : '보고서를 생성하거나 다운로드하지 못했습니다. 검사 결과와 브라우저 다운로드 설정을 확인하세요.');
    }
  }

  function exportAnalystReviewBackup() {
    if (state === 'scanning' || !scan || !scanContext) return;
    if (includeBackupNotes && !window.confirm('분석가 메모에는 내부 코드 정보나 민감정보가 포함될 수 있습니다. 저장한 JSON 파일은 디스크에 남으므로 외부 공유 전에 내용을 확인하세요. 메모를 포함할까요?')) {
      setBackupMessage('메모 포함을 확인하지 않아 백업을 취소했습니다.'); return;
    }
    try {
      const json = createAnalystReviewBackup(scanContext, scan, analystReviews, includeBackupNotes);
      downloadAnalystReviewBackup(json);
      setBackupMessage(`검토 기록 백업을 다운로드했습니다: ${ANALYST_REVIEW_BACKUP_FILENAME}`);
    } catch (error) {
      setBackupMessage(error instanceof Error && error.message === 'backup_size_limit_exceeded'
        ? '백업이 256 KiB 제한을 초과해 전체 다운로드를 취소했습니다.'
        : '검토 기록 백업을 만들거나 다운로드하지 못했습니다. 현재 검사 데이터를 확인하세요.');
    }
  }

  async function importAnalystReviewBackup(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    if (!file || !scan || !scanContext || state === 'scanning') return;
    const selectedScan = scan;
    const selectedContext = scanContext;
    setBackupPreview(null); setBackupMessage(''); setBackupSkippedIds(new Set()); setBackupAppliedIds(new Set());
    if (file.size > MAX_ANALYST_REVIEW_BACKUP_BYTES) { setBackupMessage('파일이 256 KiB 제한을 초과합니다. 현재 검토 기록은 변경되지 않았습니다.'); return; }
    try {
      const parsed = parseAnalystReviewBackup(new Uint8Array(await file.arrayBuffer()));
      if (currentScanRef.current !== selectedScan || currentScanContextRef.current !== selectedContext) { setBackupMessage('검사 결과가 변경되어 미리보기를 취소했습니다.'); return; }
      const reasons = validateBackupForRestore(parsed, selectedContext, selectedScan);
      setBackupPreview({ backup: parsed, reasons, scan: selectedScan, context: selectedContext, fileName: file.name.replace(/[\p{C}]/gu, '�').slice(0, 128) });
      setBackupMessage(reasons.length ? '백업은 읽었지만 현재 검사에 적용할 수 없습니다.' : '백업을 검증했습니다. 아직 어떤 기록도 적용되지 않았습니다.');
    } catch (error) {
      const code = error instanceof Error ? error.message : '';
      const messages: Record<string, string> = {
        backup_size_limit_exceeded: '파일이 256 KiB 제한을 초과합니다.', backup_utf8_invalid: '파일이 올바른 UTF-8 JSON이 아닙니다.',
        backup_json_invalid: 'JSON 문법을 확인할 수 없습니다.', backup_schema_invalid: '지원하지 않는 스키마이거나 허용되지 않은 필드가 있습니다.',
        backup_duplicate_key: '중복된 JSON 필드가 있습니다.', backup_depth_limit_exceeded: 'JSON 구조가 허용된 중첩 깊이를 초과합니다.',
        backup_context_invalid: '백업의 검사 문맥이 올바르지 않습니다.', backup_counts_invalid: '백업의 Finding 개수가 일치하지 않습니다.',
        backup_finding_invalid: '백업의 Finding 또는 검토 기록 항목을 검증하지 못했습니다.',
      };
      setBackupMessage(`${messages[code] ?? '백업 파일을 검증하지 못했습니다.'} 현재 검토 기록은 변경되지 않았습니다.`);
    }
  }

  function applyBackupFinding(findingId: string) {
    if (!backupPreview || backupPreview.reasons.length || backupPreview.scan !== scan || backupPreview.context !== scanContext || state === 'scanning') {
      setBackupMessage('검사 결과가 변경되었거나 문맥이 일치하지 않아 적용할 수 없습니다.'); setBackupPreview(null); return;
    }
    const saved = backupPreview.backup.findings.find((item) => item.finding_id === findingId);
    if (!saved || !scan?.findings.some((item) => item.finding_id === findingId)) return;
    const current = getAnalystReviewEntry(analystReviews, scan.findings, findingId);
    const hasCurrentRecord = analystReviews.has(findingId);
    const replaces = hasCurrentRecord && (current.status !== saved.review_status || (saved.note !== undefined && current.note !== saved.note));
    if (replaces && !window.confirm(`현재 Finding의 검토 상태${saved.note !== undefined ? ' 또는 메모' : ''}를 백업 기록으로 덮어씁니다. 계속하시겠습니까?`)) return;
    let next = setAnalystReviewStatus(analystReviews, scan.findings, findingId, saved.review_status);
    if (!next) return;
    if (saved.note !== undefined) {
      const update = setAnalystReviewNote(next, scan.findings, findingId, saved.note);
      if (!update.accepted) { setBackupMessage('메모를 적용할 수 없습니다. 현재 기록은 유지됩니다.'); return; }
      next = update.state;
    }
    setAnalystReviews(next);
    setBackupAppliedIds((previous) => new Set(previous).add(findingId));
    setBackupMessage('선택한 Finding의 외부 백업 기록을 적용했습니다. 이는 현재 코드에 대한 보안 판정을 의미하지 않습니다.');
  }

  const selectedProfile = options?.rule_profiles.find((item) => item.id === profileId);
  const contextChanged = Boolean(scanContext && (targetId !== scanContext.targetId || profileId !== scanContext.ruleProfileId));
  const apiStatusLabel = health === 'connected' ? 'API 연결됨' : health === 'checking' ? 'API 확인 중' : 'API 연결 안 됨';
  const optionsStatusLabel = health === 'checking'
    ? '검사 옵션 불러오는 중'
    : health === 'offline'
      ? '서버 연결 확인 필요'
      : options?.targets.length && options.rule_profiles.length
        ? '검사 옵션 준비됨'
        : '선택 가능한 검사 옵션 없음';
  const sidebarStatusLabel = `${apiStatusLabel} · ${optionsStatusLabel}`;
  const pageTitle = activeView === 'start' ? '코드 보안 검사' : activeView === 'results' ? '검사 결과' : '사용 안내';
  const navigate = (view: WorkspaceView) => { setActiveView(view); setMobileNavOpen(false); if (typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 760px)').matches) mobileMenuButton.current?.focus(); };
  return <div className="app-shell ui-d2 ui-d5a">
    <header className="topbar mobile-topbar">
      <button ref={mobileMenuButton} className="sidebar-toggle mobile-menu-toggle" type="button" aria-label="내비게이션 열기" aria-expanded={mobileNavOpen} aria-controls="workspace-sidebar" onClick={() => setMobileNavOpen((open) => !open)}><Icon name="menu"/></button>
      <a className="brand" href="#main-content" aria-label="AI Code Security Analyzer">
        <span className="brand-emblem" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M20 2 35 11v18l-15 9L5 29V11z"/><path d="m20 9 9 5v12l-9 5-9-5V14z"/><circle cx="20" cy="20" r="3"/></svg></span>
      </a>
    </header>
    {mobileNavOpen && <button type="button" className="sidebar-backdrop" aria-label="내비게이션 닫기" onClick={() => setMobileNavOpen(false)}/>}
    <div className={`workspace-shell ${sidebarCollapsed ? 'sidebar-is-collapsed' : ''} ${mobileNavOpen ? 'mobile-nav-open' : ''}`}>
      <aside id="workspace-sidebar" className="workspace-sidebar" role={mobileNavOpen ? 'dialog' : 'complementary'} aria-modal={mobileNavOpen || undefined} aria-label="주 메뉴">
        <div className="sidebar-brand-row">
          <a className="brand sidebar-brand" href="#main-content" aria-label="AI Code Security Analyzer">
            <span className="brand-emblem" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M20 2 35 11v18l-15 9L5 29V11z"/><path d="m20 9 9 5v12l-9 5-9-5V14z"/><circle cx="20" cy="20" r="3"/></svg></span>
            <span className="sidebar-brand-name">AI Code Security</span>
          </a>
        </div>
        <div className="sidebar-heading"><span className="sidebar-section-label">작업 공간</span><button className="sidebar-toggle collapse-toggle" type="button" aria-label={sidebarCollapsed ? '사이드바 펼치기' : '사이드바 접기'} aria-expanded={!sidebarCollapsed} onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}><Icon name="collapse"/></button></div>
        <nav className="sidebar-nav" aria-label="화면 이동">
          <button type="button" className={`nav-item ${activeView === 'start' ? 'active' : ''}`} aria-current={activeView === 'start' ? 'page' : undefined} title={sidebarCollapsed ? '검사 시작' : undefined} onClick={() => navigate('start')}><Icon name="play"/><span>검사 시작</span></button>
          <button type="button" className={`nav-item ${activeView === 'results' ? 'active' : ''}`} aria-current={activeView === 'results' ? 'page' : undefined} title={sidebarCollapsed ? '검사 결과' : undefined} onClick={() => navigate('results')}><Icon name="results"/><span>검사 결과</span>{scan && <span className="nav-result-count">{scan.displayed_finding_count}</span>}</button>
          <button type="button" className={`nav-item ${activeView === 'guide' ? 'active' : ''}`} aria-current={activeView === 'guide' ? 'page' : undefined} title={sidebarCollapsed ? '사용 안내' : undefined} onClick={() => navigate('guide')}><Icon name="book"/><span>사용 안내</span></button>
        </nav>
        <div className={`sidebar-footnote ${health}`} role="status" aria-live="polite" aria-atomic="true" aria-label={sidebarStatusLabel} title={sidebarCollapsed ? sidebarStatusLabel : undefined}>
          <span className={`status-indicator ${health}`} aria-hidden="true" />
          <span className="sidebar-status-copy"><strong>{apiStatusLabel}</strong><small>{optionsStatusLabel}</small></span>
        </div>
      </aside>
      <main id="main-content" className={`dashboard-main d2-main d2-view-${activeView}`}>
      <div className="workspace-title"><div><h1>{pageTitle}</h1></div>{activeView === 'start' ? <p>등록된 프로젝트와 규칙을 선택해 검사합니다.</p> : activeView === 'results' ? <p>현재 브라우저 세션의 결과만 표시합니다.</p> : <p>검사 순서와 결과 해석 기준을 확인하세요.</p>}</div>
      {activeView === 'start' && <>
      <section className={`mission-deck ${scan ? 'mission-deck-compact' : ''}`} aria-labelledby="scan-config-title">
        <div className="deck-heading"><h2 className="eyebrow" id="scan-config-title">검사 설정</h2><details className="investigation-mode-disclosure">
          <summary>소멸 근거 조사 선택</summary>
          <fieldset className="investigation-mode-picker" aria-describedby="investigation-mode-help">
            <legend>검사 방식</legend>
            <label><input type="radio" name="scan-mode" value="standard" checked={!investigationMode} onChange={() => changeInvestigationMode(false)} disabled={state === 'scanning'}/> 일반 검사</label>
            <label><input type="radio" name="scan-mode" value="investigation" checked={investigationMode} onChange={() => changeInvestigationMode(true)} disabled={state === 'scanning'}/> 소멸 근거 조사</label>
            <p id="investigation-mode-help">두 검사에서 관찰된 Finding 차이를 추가 증거와 함께 확인합니다. 서버 메모리에 최대 15분 임시 보관되며, 코드 수정이나 취약점 해결을 확정하지 않습니다.</p>
          </fieldset>
        </details></div>
        <form onSubmit={runScan} className="mission-form">
          <label className="mission-control project-control"><span className="control-label"><Icon name="folder"/> 검사 대상</span><span className="select-control"><select aria-label="검사 대상" value={targetId} onChange={(e) => setTargetId(e.target.value)} disabled={!options || options.targets.length === 0 || state === 'scanning'} required aria-describedby="target-help"><option value="" disabled>{options ? '등록된 프로젝트가 없습니다' : '서버 연결 후 목록을 불러옵니다'}</option>{options?.targets.map((target) => <option key={target.id} value={target.id}>{target.label}</option>)}</select><span className="select-caret" aria-hidden="true"/></span><small id="target-help">등록된 프로젝트만 검사할 수 있습니다.</small></label>
          <label className="mission-control rules-control"><span className="control-label"><Icon name="layers"/> 규칙 모음</span><span className="select-control"><select aria-label="검사 규칙 모음" value={profileId} onChange={(e) => setProfileId(e.target.value)} disabled={!options || options.rule_profiles.length === 0 || state === 'scanning'} required aria-describedby={selectedProfile?.experimental ? 'profile-help' : undefined}><option value="" disabled>{options ? '사용 가능한 규칙이 없습니다' : '서버 연결 후 목록을 불러옵니다'}</option>{options?.rule_profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.experimental ? 'Experimental · ' : ''}{profile.label}</option>)}</select><span className="select-caret" aria-hidden="true"/>{selectedProfile?.experimental && <small id="profile-help">실험 규칙이며 정확도는 충분히 검증되지 않았습니다.</small>}</span></label>
          <label className="mission-control token-control-group"><span className="control-label"><Icon name="key"/> 로컬 API 토큰</span><span className="token-control token-input-control"><input aria-label="로컬 API 토큰" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} placeholder="서버 토큰 입력" aria-describedby="token-help" disabled={state === 'scanning'} /><button type="button" className="button clear-token" onClick={clearToken} disabled={!token || state === 'scanning'} aria-label="화면의 API 토큰 지우기">지우기</button></span><small id="token-help">서버에서 발급한 토큰을 입력하세요.</small><details className="token-security-help"><summary>토큰 보관 및 전송</summary><p id="token-security-help">토큰은 브라우저 메모리에만 보관되고 요청 헤더로 전송됩니다. 새로고침하면 사라지며, 커밋하거나 공유하지 마세요.</p></details></label>
          <button className="button primary run-button launch-action" type="submit" disabled={!options || !targetId || !profileId || !token || state === 'scanning'}>{state === 'scanning' ? <><span className="spinner" aria-hidden="true" /> 검사 중</> : <><Icon name="play"/> 검사 실행</>}</button>
        </form>
      </section>
      <section className="launch-brief d2-start-brief" aria-label="검사 결과 유의사항"><div className="launch-brief-copy"><h2 id="launch-title">탐지 결과는 검토 후보입니다.</h2><p>실제 취약점 여부는 파일 위치와 근거를 확인해 판단하세요.</p></div><ol className="launch-steps sr-only" aria-label="검사 단계"><li>대상 선택</li><li>규칙 검사</li><li>결과 검토</li></ol></section>
      </>}
      {bootstrapError && <div className="alert error connection-alert" role="alert"><span>{bootstrapError}</span><button className="button secondary retry-button" type="button" onClick={() => { setHealth('checking'); setConnectionAttempt((attempt) => attempt + 1); }} disabled={health === 'checking'}>{health === 'checking' ? '연결 확인 중' : '다시 연결'}</button></div>}
      {message && ['unauthorized','scan_already_running','connection_error','failed'].includes(state) && <div className="alert error request-feedback" role="alert">{message}</div>}
      {contextChanged && scanContext && <div className="alert warning" role="alert">현재 화면의 결과는 이전 검사 설정({scanContext.targetLabel} · {scanContext.experimental ? '실험 · ' : ''}{scanContext.ruleProfileLabel})에서 생성됐습니다. 현재 선택한 설정({options?.targets.find((target) => target.id === targetId)?.label ?? '알 수 없는 대상'} · {selectedProfile?.experimental ? 'Experimental · ' : ''}{selectedProfile?.label ?? '알 수 없는 규칙'})의 결과는 아직 없습니다. 확인하려면 새 검사를 실행하세요.</div>}
      {activeView === 'guide' && <div className="guide-workspace guide-document">
        <section className="guide-section guide-method"><h2>검사 방법</h2><QuickStart /></section>
        <section className="guide-section guide-result-guide"><h2>검사 결과 이해하기</h2><div className="guide-result-copy">
          <ul className="guide-limit-list"><li>탐지된 항목은 규칙에 일치해 검토가 필요한 후보입니다. 실제 취약점으로 확정된 것은 아닙니다.</li><li>실제 영향과 악용 가능성은 파일 위치와 근거를 확인해야 판단할 수 있습니다.</li><li>후보가 0건이어도 프로젝트 안전성이 보장되는 것은 아닙니다.</li></ul>
          <p className="guide-session-note">검사 결과는 현재 브라우저 세션에서만 확인할 수 있습니다. 새로고침하거나 창을 닫으면 복원되지 않습니다.</p>
        </div></section>
        <section className="guide-section guide-additional" aria-labelledby="guide-additional-title"><h2 id="guide-additional-title">추가 안내</h2><ServerAdminSettings /><SecurityGlossary /></section>
      </div>}
      <div className="live-message sr-only" role="status" aria-live="polite" aria-atomic="true">{message}</div>
      {activeView === 'results' && !scan && <>
        {baselineSnapshot && <ScanComparisonPanel baseline={baselineSnapshot} current={null} comparison={comparison} followup={rescanFollowup} onSetBaseline={setCurrentAsBaseline} onClearBaseline={clearBaseline} onExport={exportComparisonReport} onOpenCurrentFinding={openCurrentFindingFromComparison} exportMessage={comparisonExportMessage} exporting={state === 'scanning'} investigation={{ mode: investigationMode, baselineReady: false, currentReady: false, status: investigationState, evaluation: investigationEvaluation, message: investigationMessage, onEvaluate: investigateFindingChanges, onRelease: releaseInvestigation }} />}
        <section className="results-empty-state" aria-labelledby="empty-results-title"><span className="empty-icon" aria-hidden="true"><Icon name={state === 'scanning' ? 'pulse' : 'results'}/></span><div><h2 id="empty-results-title">{state === 'scanning' ? '검사가 진행 중입니다' : '아직 검사 결과가 없습니다.'}</h2><p>{state === 'scanning' ? '검사가 끝나면 결과가 여기에 표시됩니다.' : '검사를 실행하면 이곳에서 결과를 확인할 수 있습니다.'}</p>{state !== 'scanning' && <button type="button" className="button primary" onClick={() => navigate('start')}><Icon name="play"/> 검사 시작</button>}</div></section>
      </>}
      {activeView === 'results' && scan && <div className="d2-results-workspace">
        {scanContext && <section className="scan-context panel glass-surface" aria-label="이 결과를 생성한 검사 설정"><div className="context-copy"><h2 className="sr-only">검사 정보</h2><p className="eyebrow">검사 설정 요약</p><p className="context-primary"><strong>{scanContext.targetLabel}</strong><span className="context-divider" aria-hidden="true">/</span><strong>{scanContext.experimental ? '실험 · ' : ''}{scanContext.ruleProfileLabel}</strong></p><p className="context-received-at">결과 수신: {new Date(scanContext.receivedAt).toLocaleString()}</p><details className="context-identifiers-disclosure"><summary>검사 내부 ID</summary><div className="context-identifiers"><span>대상 ID <code>{scanContext.targetId}</code></span><span>규칙 ID <code>{scanContext.ruleProfileId}</code></span></div></details></div><div className="context-actions"><button type="button" className="button secondary" aria-label="현재 검사 결과 내보내기" onClick={exportResults}><Icon name="download"/> 결과 내보내기</button><button type="button" className="button tertiary" aria-label="결과 지우기" onClick={clearResults}>결과 지우기</button></div>
        </section>}
        {investigationMode && <section className="investigation-evidence-notice" role="status" aria-live="polite"><strong>{currentEvidence?.snapshot.scan === scan ? '현재 응답에 서버 조사 증거가 연결됐습니다.' : '다음 검사를 조사 모드로 실행해야 증거를 보관합니다.'}</strong><p>서버 메모리에 최대 15분 보관됩니다. 로컬 API 토큰은 사용자별 격리를 제공하지 않으며, 증거는 화면 새로고침 뒤 복원되지 않습니다.</p>{investigationMessage && <p>{investigationMessage}</p>}</section>}
        <section className={`scan-banner ${scan.scan_status}`} aria-labelledby="scan-result-title"><div className="scan-state-copy"><p className="eyebrow">검사 상태 {scan.semgrep_version ? `· Semgrep ${scan.semgrep_version}` : '· 버전 확인 불가'}</p><h2 id="scan-result-title">{statusLabels[scan.scan_status] ?? '알 수 없는 검사 상태'}</h2></div><span className={`state-pill ${scan.scan_status}`}>{scan.completed ? '완료' : scan.scan_status === 'partial' ? '일부만 완료' : '완료되지 않음'}</span></section>
        <ScanStatusGuidance scan={scan} />
        {scan.omitted_finding_count > 0 && <p className="alert warning scan-omission-note" role="alert">{scan.omitted_finding_count}개 Finding이 생략되어 목록과 검토 현황에 포함되지 않았습니다. 생략 항목의 개별 근거는 확인할 수 없습니다.</p>}
        <section className="overview-grid analyst-overview analyst-overview-core" aria-label="핵심 검사 수치"><Metric label="검토 후보" value={scan.finding_count} note="취약점 확정 수 아님"/><Metric label="표시된 결과" value={scan.displayed_finding_count} note="현재 응답"/><Metric label="생략된 결과" value={scan.omitted_finding_count} note="개별 근거 미확인"/></section>
        <section className="findings-section" aria-labelledby="findings-heading">
          <div className="results-heading"><div className="results-title"><h2 id="findings-heading">발견 항목 <span className="count-chip">{scan.finding_count}건</span></h2>{scan.omitted_finding_count > 0 && <p>목록에는 최대 50건까지 표시됩니다.</p>}</div><div className="filter-row" role="group" aria-label="Finding 검색 및 필터">
            <div className="filter-search-row"><label className="filter-control search-field"><span>검색: 파일 경로 또는 규칙</span><span className="filter-input-wrap"><Icon name="search"/><input type="search" aria-label="검색" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="파일 경로·규칙" /></span></label></div>
            <div className="filter-select-row">
            <label className="filter-control"><span>분석가 검토</span><select id="analyst-review-status" aria-label="분석가 검토" value={analystReviewFilter} onChange={(e) => setAnalystReviewFilter(e.target.value as AnalystReviewFilter)}><option value="all">전체</option><option value="pending">검토 대기</option><option value="needs_followup">추가 확인 필요</option><option value="reviewed">검토 완료</option></select></label>
            <label className="filter-control"><span>심각도</span><select aria-label="심각도" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}><option value="all">모두</option>{severityOrder.map((x) => <option key={x} value={x}>{severityLabels[x]}</option>)}</select></label>
            <label className="filter-control"><span>탐지 유형</span><select aria-label="탐지 유형" value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}><option value="all">모두</option>{Object.entries(kindLabels).map(([key,value]) => <option key={key} value={key}>{value}</option>)}</select></label>
            <label className="filter-control"><span>검증 상태</span><select aria-label="검증 상태" value={verificationFilter} onChange={(e) => setVerificationFilter(e.target.value)}><option value="all">모두</option><option value="unverified">미검증</option></select></label>
            </div>
          </div></div>
          {scan.finding_count === 0 ? <div className="empty-state panel glass-surface"><span className="empty-icon" aria-hidden="true"><Icon name="check"/></span><div><h3>발견 항목이 없습니다</h3><p>이번 검사에서 후보가 나오지 않았습니다. 검사되지 않은 문제까지 안전하다는 뜻은 아닙니다.</p></div></div> : <div className="results-layout"><section className="finding-list data-console" aria-label="Finding 목록" tabIndex={0}><div className="list-caption"><span>검토 후보 목록</span><span>{visibleFindings.length} / {scan.displayed_finding_count} 표시</span></div>{visibleFindings.length === 0 ? <p className="no-filter-results">검색 또는 필터와 일치하는 결과가 없습니다.</p> : visibleFindings.map((finding) => <FindingRow key={finding.finding_id} finding={finding} reviewStatus={getAnalystReviewEntry(analystReviews, scan.findings, finding.finding_id).status} selected={selected?.finding_id === finding.finding_id} onSelect={() => { setSelectedId(finding.finding_id); setAnalystNoteError(''); }} />)}</section>
            <section className="detail-panel review-hud" aria-label="선택한 Finding 상세" tabIndex={0}>{selected ? <FindingDetail finding={selected} triage={scanTriage?.findings.find((item) => item.findingId === selected.finding_id)} reviewEntry={getAnalystReviewEntry(analystReviews, scan.findings, selected.finding_id)} importedFromBackup={backupAppliedIds.has(selected.finding_id)} noteError={analystNoteError} onStatusChange={(next) => updateAnalystStatus(selected.finding_id, next)} onNoteChange={(note) => updateAnalystNote(selected.finding_id, note)}/> : <div className="select-prompt"><span aria-hidden="true"><Icon name="cursor"/></span><p>{selectedId ? '현재 선택한 항목은 필터에서 제외되었습니다. 필터를 바꾸거나 목록에서 다른 항목을 선택하세요.' : '왼쪽 목록에서 항목을 선택하면 근거와 검토할 내용을 볼 수 있습니다.'}</p></div>}</section></div>}
        </section>
        <details className="overview-analysis-details" role="group" aria-label="심각도 및 분석가 검토 상세">
          <summary>심각도 분포와 분석가 검토 현황</summary>
          <div className="overview-analysis-grid" role="group" aria-label="검사 분석 요약"><section className="severity-card" aria-labelledby="severity-heading"><div className="severity-heading"><Icon name="pulse"/><h3 id="severity-heading">심각도 분포</h3></div><div className="severity-counts">{severityOrder.map((severity) => <span key={severity} className={`severity-count ${severity}`}><i className={`severity-dot ${severity}`} aria-hidden="true"/><span>{severityLabels[severity]}</span><b>{scan.severity_counts[severity]}</b></span>)}</div><small>Semgrep 분류 · 악용 여부 미확인</small></section>
            <section className="analyst-review-summary" aria-labelledby="analyst-review-heading">
              <div className="analyst-review-summary-heading"><h2 id="analyst-review-heading">분석가 검토 현황</h2><span>현재 응답 · {scan.findings.length}건</span></div>
              <div className="analyst-review-counts">{(['pending', 'needs_followup', 'reviewed'] as const).map((status) => <div className={`analyst-review-count ${status}`} key={status}><span>{analystReviewLabels[status]}</span><strong>{analystReviewCounts[status]}건</strong></div>)}</div>
              <p className="analyst-review-scope">검토 상태는 취약점 확정·수정 완료가 아닙니다.</p>
              {scan.omitted_finding_count > 0 && <p className="analyst-review-scope">생략된 {scan.omitted_finding_count}개는 포함하지 않습니다.</p>}
            </section></div>
        </details>
        <ScanComparisonPanel baseline={baselineSnapshot} current={currentSnapshot} comparison={comparison} followup={rescanFollowup} onSetBaseline={setCurrentAsBaseline} onClearBaseline={clearBaseline} onExport={exportComparisonReport} onOpenCurrentFinding={openCurrentFindingFromComparison} exportMessage={comparisonExportMessage} exporting={state === 'scanning'} investigation={{ mode: investigationMode, baselineReady: Boolean(baselineEvidence && baselineEvidence.snapshot === baselineSnapshot), currentReady: Boolean(currentEvidence && currentEvidence.snapshot.scan === scan && currentEvidence.snapshot.context === scanContext), status: investigationState, evaluation: investigationEvaluation, message: investigationMessage, onEvaluate: investigateFindingChanges, onRelease: releaseInvestigation }} />
        <section className="result-export-workspace" aria-label="보고서와 검토 기록 내보내기"><h2>보고서 및 검토 기록</h2><div className="export-note">현재 응답에 포함된 항목만 내보냅니다. 공유 전 파일을 확인하세요.{scan.omitted_finding_count > 0 ? ' 최대 50건까지 포함됩니다.' : ''}{' '}<details className="sarif-export-tool"><summary>SARIF 내보내기</summary><div className="sarif-export-options"><p>현재 검사 응답의 {scan.displayed_finding_count}개 Finding을 SARIF 2.1.0으로 다운로드합니다. 생략된 Finding은 {scan.omitted_finding_count}개입니다. 취약점 확정 결과가 아니며 GitHub 자동 업로드를 수행하지 않습니다.</p><p className="analyst-report-warning">파일 경로와 규칙 ID가 포함됩니다. 외부 공유 전에 내용을 확인하세요.</p>{codeScanningPreflight && <CodeScanningPreflightDetails preflight={codeScanningPreflight}/>}<button type="button" className="button secondary" aria-label="SARIF 다운로드" onClick={exportSarif} disabled={state === 'scanning'}><Icon name="download"/> SARIF 다운로드</button>{sarifExportMessage && <p className="export-feedback" role="status">{sarifExportMessage}</p>}</div></details><details className="analyst-report-export"><summary>분석가 검토 기록 내보내기</summary><div className="analyst-review-export-options"><label><input type="checkbox" aria-label="보고서 메모 포함" checked={includeAnalystNotes} onChange={(event) => { setIncludeAnalystNotes(event.target.checked); setAnalystReviewExportMessage(''); }}/> 메모 포함</label>{includeAnalystNotes && <p className="analyst-report-warning">분석가 메모에는 내부 코드 정보나 민감정보가 포함될 수 있습니다. 다운로드 파일은 디스크에 남으므로 외부 공유 전에 확인하세요.</p>}<button type="button" className="button secondary" aria-label="분석가 검토 기록 내보내기 · Markdown 다운로드" onClick={exportAnalystReviewReport} disabled={state === 'scanning'}><Icon name="download"/> Markdown 다운로드</button>{analystReviewExportMessage && <p className="export-feedback" role="status">{analystReviewExportMessage}</p>}</div></details><details className="analyst-backup-tool"><summary>검토 기록 백업 및 복원</summary><div className="analyst-backup-controls"><p>JSON은 검토 상태를 다시 참고하기 위한 백업입니다. 다운로드 파일은 디스크에 남으며 자동 저장되지 않습니다.</p><label><input type="checkbox" aria-label="JSON 백업에 메모 포함" checked={includeBackupNotes} onChange={(event) => { setIncludeBackupNotes(event.target.checked); setBackupMessage(''); }}/> JSON 백업에 메모 포함</label>{includeBackupNotes && <p className="analyst-report-warning">메모에 내부 코드 정보나 민감정보가 포함될 수 있습니다. 다운로드 파일은 디스크에 남으므로 외부 공유 전에 확인하세요.</p>}<button type="button" className="button secondary" aria-label="검토 기록 백업 JSON 다운로드" onClick={exportAnalystReviewBackup} disabled={state === 'scanning'}><Icon name="download"/> 검토 기록 백업 JSON 다운로드</button><label className="backup-file-label" htmlFor="analyst-review-backup-file">검토 기록 불러오기(JSON)</label><input id="analyst-review-backup-file" className="backup-file-input" type="file" accept=".json,application/json" aria-describedby="backup-file-help" onChange={importAnalystReviewBackup} disabled={state === 'scanning'}/><small id="backup-file-help">최대 256 KiB. 파일은 브라우저 메모리에서만 읽으며 서버로 전송하지 않습니다.</small>{backupMessage && <p className="export-feedback" role="status">{backupMessage}</p>}{backupPreview && <section className="backup-preview" aria-label="검토 기록 복원 미리보기"><h3>외부 백업 미리보기</h3><p>파일: {backupPreview.fileName}</p><p>{backupPreview.backup.findings.length}개 Finding · 대기 {backupPreview.backup.findings.filter((item) => item.review_status === 'pending').length} · 추가 확인 {backupPreview.backup.findings.filter((item) => item.review_status === 'needs_followup').length} · 검토 완료 {backupPreview.backup.findings.filter((item) => item.review_status === 'reviewed').length}건</p><p>{backupPreview.backup.findings.some((item) => item.note !== undefined) ? '메모 포함' : '메모 제외'}</p><p>적용 가능: {backupPreview.reasons.length ? 0 : backupPreview.backup.findings.length}건 · 현재 기록과 충돌: {scan ? backupPreview.backup.findings.filter((item) => { const existing = getAnalystReviewEntry(analystReviews, scan.findings, item.finding_id); return analystReviews.has(item.finding_id) && (existing.status !== item.review_status || (item.note !== undefined && existing.note !== item.note)); }).length : 0}건</p><p className="analyst-report-warning">문맥이 일치해도 코드 내용이 같다는 뜻은 아닙니다. 가져온 검토 기록은 현재 코드의 보안 판정이나 수정 여부를 증명하지 않습니다.</p>{backupPreview.reasons.length > 0 ? <div role="alert"><strong>복원 차단</strong><ul>{backupPreview.reasons.map((reason) => <li key={reason}>{restoreReasonLabels[reason]}</li>)}</ul></div> : <details className="backup-finding-preview"><summary>Finding별 기록 확인 ({backupPreview.backup.findings.length})</summary><ul>{backupPreview.backup.findings.map((item) => { const currentEntry = scan ? getAnalystReviewEntry(analystReviews, scan.findings, item.finding_id) : { status: 'pending' as const, note: '' }; const applied = backupAppliedIds.has(item.finding_id); const skipped = backupSkippedIds.has(item.finding_id); return <li key={item.finding_id}><strong>{item.rule_id}</strong><span>{item.file_path ?? '위치 확인 불가'}{item.line_number ? `:${item.line_number}` : ''}</span><span>백업: {analystReviewLabels[item.review_status]} · 현재: {analystReviewLabels[currentEntry.status]}</span>{item.note !== undefined && <p>백업 메모 미리보기: {item.note || '(빈 메모)'}</p>}<p>{currentEntry.note ? '현재 메모 있음' : '현재 메모 없음'}</p><button type="button" className="button secondary" onClick={() => applyBackupFinding(item.finding_id)} disabled={state === 'scanning' || applied || skipped}>{applied ? '적용됨' : skipped ? '건너뜀' : '이 기록 적용'}</button><button type="button" className="button tertiary" onClick={() => setBackupSkippedIds((previous) => new Set(previous).add(item.finding_id))} disabled={applied || skipped}>{skipped ? '건너뜀' : '건너뛰기'}</button></li>; })}</ul></details>}</section>}</div></details></div>{exportMessage && <p className="export-feedback" role="status">{exportMessage}</p>}</section>
      </div>}
      </main>
    </div>
  </div>;
}

function Icon({name}:{name:'sliders'|'play'|'book'|'download'|'pulse'|'search'|'check'|'cursor'|'radar'|'folder'|'layers'|'key'|'results'|'menu'|'collapse'}) {
  const paths:Record<string,React.ReactNode>={
    sliders:<><path d="M4 7h8m4 0h4M4 17h4m4 0h8"/><circle cx="14" cy="7" r="2"/><circle cx="10" cy="17" r="2"/></>,play:<path d="m8 5 11 7-11 7z"/>,
    book:<><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v17H6.5A2.5 2.5 0 0 0 4 22z"/><path d="M4 5.5v14A2.5 2.5 0 0 1 6.5 17H20"/></>,
    download:<><path d="M12 3v12m0 0 4-4m-4 4-4-4"/><path d="M5 17v4h14v-4"/></>,pulse:<><path d="M3 12h4l3-8 4 16 3-8h4"/><circle cx="12" cy="12" r="9"/></>,
    search:<><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></>,check:<path d="m5 12 4 4L19 6"/>,cursor:<path d="m5 3 14 9-7 1-3 7z"/>,
    radar:<><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="m12 12 6-6"/><circle cx="12" cy="12" r="1"/></>,
    folder:<><path d="M3 6.5h7l2 2h9v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M3 8.5h18"/></>,
    layers:<><path d="m12 3 9 5-9 5-9-5z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/></>,
    key:<><circle cx="8" cy="15" r="4"/><path d="m11 12 9-9m-3 3 3 3m-6 0 3 3"/></>,
    results:<><path d="M4 5h16M4 12h16M4 19h16"/><circle cx="7" cy="5" r="1"/><circle cx="7" cy="12" r="1"/><circle cx="7" cy="19" r="1"/></>,
    menu:<><path d="M4 6h16M4 12h16M4 18h16"/></>,
    collapse:<><path d="M4 5h16v14H4zM9 5v14m4-9 3 2-3 2"/></>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
function Metric({label,value,note}:{label:string;value:number;note:string}) { return <div className="panel metric"><span className="metric-label">{label}</span><strong>{value.toLocaleString('ko-KR')}</strong><small>{note}</small></div>; }
function CodeScanningPreflightDetails({preflight}:{preflight:CodeScanningPreflight}) {
  const status = preflight.uploadReadiness === 'BLOCKED' ? 'BLOCKED · 차단 조건 있음' : 'REQUIRES_VERIFICATION · 추가 확인 필요';
  const checks = [
    ['sarifStructure', 'SARIF 2.1.0 구조'], ['ruleReferences', 'Rule ID / ruleIndex 참조'],
    ['ruleStability', '여러 실행 간 Rule ID 안정성'], ['pathFormat', '상대 경로 URI 형식'],
    ['remoteRepository', '원격 저장소 및 commit의 파일 일치'], ['repositoryCommit', '검사 소스와 Git commit 연결'],
    ['sourceSnapshot', '분석 당시 소스 스냅샷 일치'], ['fingerprints', 'Fingerprint 제공 여부'],
    ['scanScope', '검사 범위'], ['workflowPermissions', '저장소 권한과 Code Scanning 사용 가능 여부'],
    ['trustBoundary', '업로드 Workflow 신뢰 경계'],
  ] as const;
  const locationLabel = { FILE_AND_LINE: '파일과 줄 제공', FILE_WITHOUT_LINE: '파일만 제공 · 줄 번호 없음', NO_FILE_OR_LINE: '파일 위치 없음' } as const;
  return <details className="code-scanning-preflight"><summary>GitHub Code Scanning 연동 사전 확인 · {status}</summary>
    <p>OASIS SARIF 2.1.0 생성 구조와 현재 응답의 Rule 참조를 확인했습니다. 이 화면은 로컬 결과만 진단하며 GitHub에 연결하거나 업로드하지 않습니다.</p>
    <ul aria-label="GitHub Code Scanning 사전 확인 항목">{checks.map(([key, label]) => <li key={key}><strong>{preflight.checks[key].status}</strong> · {label}{key === 'scanScope' ? ` — ${preflight.scopeMessage}` : ` — ${preflight.checks[key].detail}`}</li>)}</ul>
    <details className="preflight-location-list"><summary>Finding별 위치 제공 상태 ({preflight.findingLocations.length}건)</summary>
      {preflight.findingLocations.length === 0 ? <p>현재 응답에 Finding이 없습니다. 빈 결과는 저장소 안전성의 증명이 아닙니다.</p> : <ul aria-label="Finding별 위치 제공 상태">{preflight.findingLocations.map((location) => <li key={location.findingId}><code>{location.ruleId}</code> · {locationLabel[location.state]}{location.lineNumber ? ` · ${location.lineNumber}행` : ''} · 상대 URI 형식 {location.uriFormat} · 원격 저장소 파일 일치 {location.repositoryFile}{location.uri ? ` · ${location.uri}` : ''}</li>)}</ul>}
    </details>
    <p><strong>{preflight.uploadMethods.uploadSarifAction}</strong> · GitHub Actions upload-sarif의 source checkout 및 fingerprint 보완 확인 필요</p>
    <p><strong>{preflight.uploadMethods.restApi}</strong> · REST API는 fingerprint가 없어 중복 경고 위험을 검토해야 합니다.</p>
    <p>업로드 전 저장소의 Code Scanning 사용 가능 여부, 대상 commit/ref, 파일 경로, 분석 category, 권한과 fork/PR 신뢰 경계를 확인해야 합니다. Finding ID는 GitHub fingerprint가 아닙니다.</p>
    <p>업로드 준비 상태: <strong>{status}</strong></p>
  </details>;
}
function FindingRow({finding,reviewStatus,selected,onSelect}:{finding:ApiFinding;reviewStatus:AnalystReviewStatus;selected:boolean;onSelect:()=>void}) { const location = finding.file_path ?? '위치 확인 불가'; const line = finding.line_number ? `:${finding.line_number}` : ''; const validated = finding.evidence_validation_status === 'validated'; const evidence = validated ? '근거 연결 구조 확인' : '근거 연결 확인 불가'; return <button type="button" className={`finding-row ${selected?'selected':''}`} onClick={onSelect} aria-pressed={selected}><span className={`severity-rail ${finding.severity}`} aria-hidden="true"/><span className="row-main"><span className="row-main-heading"><strong>{ruleName(finding.rule_id)}</strong><span className={`severity-label ${finding.severity}`}>{severityLabels[finding.severity]}</span></span><small className="row-location">{location}{line}</small><span className="row-secondary-meta"><code className="row-rule-id">{finding.rule_id}</code><span className="row-kind">{kindLabels[finding.finding_kind]}</span><span className="unverified-badge">미확인 후보</span><span className={`evidence-validation-label ${finding.evidence_validation_status}`}>{evidence}</span><span className={`analyst-review-badge ${reviewStatus}`}>분석가: {analystReviewLabels[reviewStatus]}</span></span></span><span className={`validation-icon ${finding.evidence_validation_status}`} title={`근거 검증 ${finding.evidence_validation_status}`} aria-hidden="true">{validated ? <svg className="validation-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d="m5 12 4 4L19 6"/></svg> : <svg className="validation-mark" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true" focusable="false"><path d="M10 4.5v7"/><circle cx="10" cy="15" r=".8" fill="currentColor" stroke="none"/></svg>}</span></button>; }
function FindingDetail({finding,triage,triageLabel='분석가 검토 가이드',reviewEntry,importedFromBackup,noteError,onStatusChange,onNoteChange}:{finding:ApiFinding;triage?:FindingTriage;triageLabel?:string;reviewEntry?:{status:AnalystReviewStatus;note:string};importedFromBackup?:boolean;noteError?:string;onStatusChange?:(status:AnalystReviewStatus)=>void;onNoteChange?:(note:string)=>void}) {
  const guidance = getFindingReviewGuidance(finding.rule_id, finding.finding_kind);
  return <article>
    <div className="detail-top"><div><p className="eyebrow">발견 항목 요약</p><h2>{ruleName(finding.rule_id)}</h2></div><span className={`severity-label ${finding.severity}`}>심각도: {severityLabels[finding.severity]}</span></div>
    <div className="detail-badges"><span>{kindLabels[finding.finding_kind]}</span><span className="unverified-badge">미검증 후보</span></div>
    <div className="detail-location"><span>확인할 파일과 위치</span><strong>{finding.file_path ?? '파일 경로를 확인할 수 없습니다'}{finding.line_number ? `:${finding.line_number}` : ''}</strong><small>이 위치는 규칙이 보고한 매치입니다. 실제 입력 위치나 위험한 함수의 인자 위치와 같다고 확인된 것은 아닙니다.</small></div>
    {reviewEntry && onStatusChange && onNoteChange && <section className="analyst-review-editor" aria-labelledby="analyst-review-editor-title"><h3 id="analyst-review-editor-title">분석가 검토</h3>{importedFromBackup && <p className="backup-origin-note" role="status">외부 백업에서 가져온 기록입니다. 현재 코드에 대한 보안 판정은 아닙니다.</p>}<label>수동 검토 상태<select aria-label="수동 검토 상태" value={reviewEntry.status} onChange={(event) => onStatusChange(event.target.value as AnalystReviewStatus)}><option value="pending">검토 대기</option><option value="needs_followup">추가 확인 필요</option><option value="reviewed">검토 완료</option></select></label><label htmlFor="analyst-note">분석가 메모<textarea id="analyst-note" aria-label="분석가 메모" aria-describedby={`analyst-note-help analyst-note-count${noteError ? ' analyst-note-error' : ''}`} value={reviewEntry.note} onChange={(event) => onNoteChange(event.target.value)} rows={4}/></label><p id="analyst-note-help" className="analyst-note-help">임시 저장: 이 탭의 메모리에만 보관되며 새 검사·결과 삭제·새로고침 시 사라집니다. 토큰, 개인정보, 비밀정보는 입력하지 마세요.</p><p id="analyst-note-count" className="analyst-note-count">UTF-8 {new TextEncoder().encode(reviewEntry.note).byteLength} / 2,048 bytes</p>{noteError && <p id="analyst-note-error" className="analyst-note-error" role="alert">{noteError}</p>}</section>}
    {finding.evidence_validation_status !== 'validated' && <div className="alert warning" role="note">근거 연결을 검증하지 못해 지원된 근거는 표시하지 않습니다. 자세한 상태와 코드는 기술 상세에서 확인할 수 있습니다.</div>}
    <section className="analyst-triage" aria-label={triageLabel}>
      <div className="analyst-triage-heading"><h3>분석가 검토 가이드</h3>{triage && <span className={`triage-recommendation ${triage.recommendation}`}>{triage.recommendationLabel}</span>}</div>
      {triage ? <>
        <p className="triage-explanation">{triage.explanation}</p>
        <p className="triage-risk-limit" role="note">검토 작업 제안이며 위험 점수·취약점 확정·자동 수정이 아닙니다. 분석가 검토 상태는 별도로 관리됩니다.</p>
        {triage.scopeNotice && <p className="triage-scope-warning" role="note">{triage.scopeNotice}</p>}
        <details className="triage-details">
          <summary>판단 근거, 단계별 검토 절차 및 권장 조치</summary>
          <div className="triage-detail-content">
            <h4>이 제안에 사용한 정보</h4><ul>{triage.basis.map((item) => <li key={item}>{item}</li>)}</ul>
            <h4>{triage.structuralEvidence.length ? '구조적으로 연결 검증된 근거' : '근거 연결 상태'}</h4>{triage.structuralEvidence.length ? <><ul>{triage.structuralEvidence.map((item) => <li key={item}>{item}</li>)}</ul><p>API의 지원 Claim 식별자: {triage.supportedClaims.length ? triage.supportedClaims.map((claim) => <code key={claim}>{claim} </code>) : '없음'}</p></> : <p>근거 연결이 검증되지 않아 지원된 근거를 표시하지 않습니다. 부족한 근거가 위험도가 낮다는 뜻은 아닙니다.</p>}
            <h4>아직 검증되지 않은 사항</h4><ul>{triage.notVerified.map((item) => <li key={item}>{item}</li>)}</ul>
            <h4>먼저 확인할 내용 · {triage.ruleTitle}</h4><p>{triage.ruleFinding}</p><ol>{triage.tasks.map((task) => <li key={task}>{task}</li>)}</ol>
            <h4>고려할 조치 방향</h4><ul>{triage.actions.map((action) => <li key={action}>{action}</li>)}</ul>
          </div>
        </details>
      </> : <>
        <p className="triage-explanation">비교 결과의 검사 범위 정보가 이 화면에 포함되지 않아 우선순위를 산출하지 않습니다. 아래는 일반적인 검토 제안입니다.</p>
        <details className="triage-details"><summary>단계별 검토 절차 및 권장 조치</summary><div className="triage-detail-content"><h4>먼저 확인할 내용 · {guidance.title}</h4><p>{guidance.finding}</p><ol>{guidance.tasks.map((task) => <li key={task}>{task}</li>)}</ol><h4>고려할 조치 방향</h4><ul>{guidance.actions.map((action) => <li key={action}>{action}</li>)}</ul></div></details>
      </>}
    </section>
    <div className="basic-evidence-limit" role="note"><strong>중요한 제한</strong><p>이 결과는 검토 후보이며 실제 취약점으로 확정되지 않았습니다. Source/Sink 위치와 전체 데이터 전달 경로는 확인되지 않았을 수 있습니다.</p></div>
    <details className="technical-details">
      <summary>기술 근거와 제한 자세히 보기</summary>
      <div className="technical-content">
        <dl className="finding-technical-meta"><div><dt>규칙 ID</dt><dd><code>{finding.rule_id}</code></dd></div><div><dt>Finding ID</dt><dd><code>{finding.finding_id}</code></dd></div><div><dt>분석 유형</dt><dd><code>{finding.finding_kind}</code></dd></div><div><dt>근거 연결 검증</dt><dd><code>{finding.evidence_validation_status}</code></dd></div><div><dt>취약점 상태</dt><dd><code>{finding.verification_status}</code></dd></div></dl>
        {finding.evidence_validation_status !== 'validated' && <div className="alert warning" role="note">근거 검증이 통과하지 않았습니다. 지원된 주장은 표시하지 않습니다.{finding.validation_error_code ? ` (${finding.validation_error_code})` : ''}</div>}
        {finding.evidence_validation_status === 'validated' && <section className="claim-section supported"><h3><span aria-hidden="true">✓</span> 확인된 구조적 근거 <small>{finding.supported_claims.length}</small></h3>{finding.supported_claims.length ? <ul>{finding.supported_claims.map((claim) => <li key={claim}><strong>{claimLabels[claim]}</strong><code>{claim}</code></li>)}</ul> : <p>지원된 주장이 없습니다.</p>}</section>}
        <section className="claim-section restricted"><h3><span aria-hidden="true">!</span> 확인되지 않았거나 지원되지 않는 내용 <small>{finding.restricted_claims.length}</small></h3>{finding.restricted_claims.length ? <ul>{finding.restricted_claims.map((claim) => <li key={claim.claim_type}><div><strong>{claimLabels[claim.claim_type]}</strong><span className="decision">{decisionLabels[claim.decision] ?? '확인 불가'}</span></div><code>{claim.claim_type} · {claim.decision}</code>{claim.reason_codes.map((reason) => <p className="reason" key={reason}>{reasonLabels[reason] ?? '추가 검토가 필요합니다.'}</p>)}</li>)}</ul> : <p>제한된 주장이 없습니다.</p>}</section>
      </div>
    </details>
  </article>;
}

const comparisonReasonLabels: Record<ComparisonBlockReason, string> = {
  baseline_missing: '비교 기준이 없습니다. 정상 완료된 검사를 기준으로 지정하세요.',
  current_missing: '비교 기준이 저장되었습니다. 검사 시작에서 같은 대상과 규칙으로 새 검사를 실행하세요.',
  same_scan_snapshot: '비교 기준이 저장되었습니다. 같은 대상과 규칙으로 새 검사를 실행하면 결과 차이를 확인할 수 있습니다.',
  baseline_not_completed: '기준 검사가 정상 완료되지 않아 비교할 수 없습니다.',
  current_not_completed: '부분 검사 또는 실패한 결과는 비교할 수 없습니다.',
  baseline_findings_omitted: '기준 응답에서 Finding이 생략되어 전체 비교를 할 수 없습니다.',
  current_findings_omitted: '현재 응답에서 Finding이 생략되어 전체 비교를 할 수 없습니다.',
  target_mismatch: '검사 대상이 서로 다릅니다.',
  rule_profile_mismatch: '규칙 모음 또는 Experimental 상태가 서로 다릅니다.',
  semgrep_version_unavailable: '두 검사 모두 Semgrep 버전을 확인할 수 있어야 합니다.',
  semgrep_version_mismatch: 'Semgrep 버전이 서로 다릅니다.',
  baseline_context_mismatch: '기준 검사 문맥과 응답 상태가 일치하지 않습니다.',
  current_context_mismatch: '현재 검사 문맥과 응답 상태가 일치하지 않습니다.',
  baseline_duplicate_finding_id: '기준 응답에 중복 Finding ID가 있어 비교를 중단했습니다.',
  current_duplicate_finding_id: '현재 응답에 중복 Finding ID가 있어 비교를 중단했습니다.',
  baseline_count_inconsistent: '기준 응답의 Finding 수가 요약과 일치하지 않습니다.',
  current_count_inconsistent: '현재 응답의 Finding 수가 요약과 일치하지 않습니다.',
};

type ComparisonCategory = keyof ComparisonGroups;
const comparisonCategoryLabels: Record<ComparisonCategory, string> = {
  currentOnly: '이번 검사에서만 관찰', shared: '양쪽에서 관찰', baselineOnly: '기준 검사에서만 관찰',
};

function receivedAtLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '시간 정보 확인 불가' : date.toLocaleString('ko-KR');
}

function ScanComparisonPanel({
  baseline, current, comparison, followup, onSetBaseline, onClearBaseline, onExport, onOpenCurrentFinding, exportMessage, exporting, investigation,
}: {
  baseline: ScanSnapshot | null;
  current: ScanSnapshot | null;
  comparison: ReturnType<typeof compareScanSnapshots>;
  followup: RescanFollowup;
  onSetBaseline: () => void;
  onClearBaseline: () => void;
  onExport: () => void;
  onOpenCurrentFinding: (findingId: string) => void;
  exportMessage: string;
  exporting: boolean;
  investigation: InvestigationPanelState;
}) {
  const [category, setCategory] = useState<ComparisonCategory>('currentOnly');
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const groups = comparison.groups;
  const items = followup.groups[category];
  const selected = items.find((item) => item.findingId === selectedFindingId) ?? items[0];
  const canSetBaseline = Boolean(current?.scan.scan_status === 'completed' && current.scan.completed);

  if (!baseline && current?.scan.scan_status === 'completed' && current.scan.completed) return <section className="scan-comparison scan-comparison-compact" aria-labelledby="scan-comparison-title">
    <div className="comparison-compact-copy"><h2 id="scan-comparison-title">검사 결과 비교</h2><span className="comparison-baseline-state">비교 기준 없음</span><p>현재 결과를 기준으로 저장한 뒤, 같은 대상과 규칙으로 다시 검사하면 결과 차이를 확인할 수 있습니다.</p></div>
    <button type="button" className="button secondary comparison-baseline-action" onClick={onSetBaseline} disabled={!canSetBaseline}>현재 결과를 비교 기준으로 저장</button>
    {investigation.mode && <InvestigationPanel baseline={baseline} current={current} comparison={comparison} state={investigation}/>}
  </section>;

  return <section className="scan-comparison" aria-labelledby="scan-comparison-title">
    <div className="comparison-heading">
      {comparison.comparable && groups ? <details className="comparison-content">
        <summary>
          <span className="comparison-title-copy"><span className="eyebrow">현재 세션에서만 유지</span><h2 id="scan-comparison-title">검사 결과 비교</h2></span>
          <span className="comparison-summary-counts">이번만 {groups.currentOnly.length} · 양쪽 {groups.shared.length} · 기준만 {groups.baselineOnly.length}</span>
        </summary>
        <div className="comparison-content-body">
          <div className="comparison-contexts">
            <ComparisonContext label="기준 검사" snapshot={baseline}/>
            <ComparisonContext label="현재 검사" snapshot={current}/>
          </div>
          <p className="comparison-limitation">Finding ID가 정확히 일치하는지만 비교합니다. 코드 이동이나 줄 번호·규칙 변경으로 분류가 달라질 수 있으며, 취약점의 신규 발생이나 해결을 확정하지 않습니다.</p>
          <div className="comparison-counts" aria-label="Finding 관찰 차이">
            {(Object.keys(comparisonCategoryLabels) as ComparisonCategory[]).map((key) => <div className={`comparison-count ${key}`} key={key}>
              <span>{comparisonCategoryLabels[key]}</span><strong>{groups[key].length}</strong>
            </div>)}
          </div>
          <div className="comparison-category-switch" role="group" aria-label="비교 항목 범주">
            {(Object.keys(comparisonCategoryLabels) as ComparisonCategory[]).map((key) => <button key={key} type="button" aria-pressed={category === key} onClick={() => setCategory(key)}>
              {comparisonCategoryLabels[key]} <span>{groups[key].length}</span>
            </button>)}
          </div>
          <div className="comparison-review">
            <section className="comparison-finding-list" aria-label={`${comparisonCategoryLabels[category]} 목록`}>
              <h3>{comparisonCategoryLabels[category]}</h3>
              {items.length === 0 ? <p>이 범주에 해당하는 항목이 없습니다.</p> : <ul>{items.map((item) => <li key={item.findingId}>
                <button type="button" className={item.findingId === selected?.findingId ? 'selected' : ''} aria-pressed={item.findingId === selected?.findingId} onClick={() => setSelectedFindingId(item.findingId)}>
                  <span className={`comparison-severity ${item.finding.severity}`}>{severityLabels[item.finding.severity]}</span>
                  <strong>{ruleName(item.finding.rule_id)}</strong>
                  <span>{item.finding.file_path ?? '파일 위치 확인 불가'}{item.finding.line_number ? `:${item.finding.line_number}` : ''}</span>
                </button>
              </li>)}</ul>}
            </section>
            <section className="comparison-finding-detail" aria-label="비교 항목 후속 검토">
              {selected ? <>
                <div className="comparison-followup-summary">
                  <p className="eyebrow">{comparisonCategoryLabels[category]}</p>
                  <h3>재검사 후속 검토</h3>
                  <dl>
                    <div><dt>규칙 ID</dt><dd><code>{selected.finding.rule_id}</code></dd></div>
                    <div><dt>위치</dt><dd>{selected.finding.file_path ?? '파일 위치 확인 불가'}{selected.finding.line_number ? `:${selected.finding.line_number}` : ''}</dd></div>
                    <div><dt>도구 심각도</dt><dd>{severityLabels[selected.finding.severity]}</dd></div>
                  </dl>
                  {selected.triage && <p><strong>현재 Triage:</strong> {selected.triage.recommendationLabel}</p>}
                  {selected.metadataSummary && <p>{selected.metadataSummary}</p>}
                  <p className="comparison-followup-limit" role="note">{selected.limitation}</p>
                  <details className="comparison-followup-tasks"><summary>권장 후속 검토 절차</summary><ol>{selected.tasks.map((task) => <li key={task}>{task}</li>)}</ol></details>
                  {selected.canOpenCurrentFinding
                    ? <button type="button" className="button secondary comparison-open-current" onClick={() => onOpenCurrentFinding(selected.findingId)}>현재 Finding 검토하기</button>
                    : <p className="comparison-readonly-note">현재 검사에 포함되지 않은 기준 Finding이므로 과거 응답 근거만 읽기 전용으로 표시합니다.</p>}
                </div>
                <FindingDetail finding={selected.finding} triage={selected.triage ?? undefined} triageLabel="비교 항목 분석가 검토 가이드"/>
              </> : <p>항목을 선택하면 후속 검토 제안과 기존 근거를 확인할 수 있습니다.</p>}
            </section>
          </div>
        </div>
      </details>
      : <div className="comparison-title-copy">
        <p className="eyebrow">현재 세션에서만 유지</p>
        <h2 id="scan-comparison-title">검사 결과 비교</h2>
      </div>}
      <button type="button" className="button secondary comparison-baseline-action" onClick={onSetBaseline} disabled={!canSetBaseline}>
        {baseline ? '현재 결과로 비교 기준 다시 저장' : '현재 결과를 비교 기준으로 저장'}
      </button>
      {baseline && <button type="button" className="button tertiary comparison-baseline-clear" onClick={onClearBaseline} disabled={exporting}>비교 기준 해제</button>}
      <button type="button" className="button secondary comparison-export-action" onClick={onExport} disabled={!comparison.comparable || !groups || exporting}>
        비교 보고서 내보내기
      </button>
    </div>

    {exportMessage && <p className="export-feedback comparison-export-feedback" role="status">{exportMessage}</p>}
    {!comparison.comparable || !groups ? <div className="comparison-blocked" role="status" aria-live="polite">
      <strong>비교 판단 불가</strong>
      <ul>{comparison.reasons.map((reason) => <li key={reason}>{comparisonReasonLabels[reason]}</li>)}</ul>
    </div> : null}
    {investigation.mode && <InvestigationPanel baseline={baseline} current={current} comparison={comparison} state={investigation}/>}
  </section>;
}

interface InvestigationPanelState {
  mode: boolean;
  baselineReady: boolean;
  currentReady: boolean;
  status: 'idle' | 'running' | 'ready' | 'error';
  evaluation: InvestigationEvaluation | null;
  message: string;
  onEvaluate: () => void;
  onRelease: () => void;
}

const investigationCategoryLabels: Record<InvestigationCategory, string> = {
  currentOnly: '이번 검사에서만 관찰', shared: '양쪽 검사에서 관찰', baselineOnly: '기준 검사에서만 관찰',
};

function InvestigationPanel({ baseline, current, comparison, state }: {
  baseline: ScanSnapshot | null;
  current: ScanSnapshot | null;
  comparison: ReturnType<typeof compareScanSnapshots>;
  state: InvestigationPanelState;
}) {
  const [category, setCategory] = useState<InvestigationCategory>('baselineOnly');
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const evaluation = state.evaluation;
  const findings = evaluation?.findings.filter((item) => item.category === category) ?? [];
  const selected = findings.find((item) => item.finding_id === selectedFindingId) ?? findings[0];
  const sourceScan = category === 'baselineOnly' ? baseline?.scan : current?.scan;
  const localFinding = selected ? sourceScan?.findings.find((finding) => finding.finding_id === selected.finding_id) : null;
  const counts = evaluation ? Object.fromEntries((Object.keys(investigationCategoryLabels) as InvestigationCategory[])
    .map((itemCategory) => [itemCategory, evaluation.findings.filter((item) => item.category === itemCategory).length])) as Record<InvestigationCategory, number> : null;
  const canEvaluate = state.baselineReady && state.currentReady && state.status !== 'running';

  return <section className="investigation-panel" aria-labelledby="investigation-title">
    <div className="investigation-panel-heading"><div><h3 id="investigation-title">소멸 근거 조사</h3><p>두 검사에 연결된 서버 증거를 비교합니다. Finding ID의 차이는 코드 동일성이나 취약점 해결을 증명하지 않습니다.</p></div>
      <div className="investigation-actions">
        <button type="button" className="button secondary" onClick={state.onEvaluate} disabled={!canEvaluate} aria-busy={state.status === 'running'}>{state.status === 'running' ? '증거 평가 중' : evaluation ? '다시 평가' : '소멸 근거 조사 실행'}</button>
        {(state.baselineReady || state.currentReady) && <button type="button" className="button tertiary" onClick={state.onRelease} disabled={state.status === 'running'}>조사 증거 해제</button>}
      </div>
    </div>
    {!state.baselineReady && <p className="investigation-guidance" role="note">이 비교 기준에는 서버 조사 증거가 없습니다. 조사 모드에서 기준 검사를 다시 실행하고 그 결과를 기준으로 저장하세요.</p>}
    {state.baselineReady && !state.currentReady && <p className="investigation-guidance" role="note">기준 증거는 보관 중입니다. 같은 프로젝트와 규칙을 조사 모드로 다시 검사하세요.</p>}
    {comparison.reasons.length > 0 && state.baselineReady && state.currentReady && <p className="investigation-guidance" role="note">화면의 일반 비교가 차단되어도 서버 평가는 실행할 수 있으며, 서버가 비교 불가로 판단하면 그 결과와 한계를 표시합니다.</p>}
    {state.message && <p className={`investigation-feedback ${state.status === 'error' ? 'error' : ''}`} role={state.status === 'error' ? 'alert' : 'status'} aria-live={state.status === 'error' ? 'assertive' : 'polite'}>{state.message}</p>}
    {evaluation && counts && <div className="investigation-result" aria-live="polite">
      <div className="investigation-assessment"><div><span>증거 비교</span><strong>{investigationAssessmentLabels[evaluation.comparability]}</strong></div><div><span>전체 평가</span><strong>{investigationAssessmentLabels[evaluation.overall_assessment]}</strong></div></div>
      <p className="investigation-safety-note">Finding 미관찰은 취약점 수정이나 해결 완료의 증거가 아닙니다. 코드 스냅샷은 수집되지 않았습니다.</p>
      <div className="comparison-counts investigation-counts" aria-label="증거 평가 Finding 범주">
        {(Object.keys(investigationCategoryLabels) as InvestigationCategory[]).map((itemCategory) => <div className={`comparison-count ${itemCategory}`} key={itemCategory}><span>{investigationCategoryLabels[itemCategory]}</span><strong>{counts[itemCategory]}</strong></div>)}
      </div>
      <div className="comparison-category-switch" role="group" aria-label="증거 평가 Finding 범주">
        {(Object.keys(investigationCategoryLabels) as InvestigationCategory[]).map((itemCategory) => <button type="button" key={itemCategory} aria-pressed={category === itemCategory} onClick={() => { setCategory(itemCategory); setSelectedFindingId(''); }}>{investigationCategoryLabels[itemCategory]} <span>{counts[itemCategory]}</span></button>)}
      </div>
      {findings.length > 1 && <ul className="investigation-finding-selector" aria-label={`${investigationCategoryLabels[category]} Finding 목록`}>
        {findings.map((item) => {
          const itemScan = category === 'baselineOnly' ? baseline?.scan : current?.scan;
          const local = itemScan?.findings.find((finding) => finding.finding_id === item.finding_id);
          return <li key={item.finding_id}><button type="button" aria-pressed={selected?.finding_id === item.finding_id} onClick={() => setSelectedFindingId(item.finding_id)}>
            <strong>{local?.rule_id ?? item.finding_id}</strong><span>{local?.file_path ?? '파일 위치 확인 불가'}{local?.line_number ? `:${local.line_number}` : ''}</span>
          </button></li>;
        })}
      </ul>}
      {selected ? <div className="investigation-finding-result">
        <h4>{investigationCategoryLabels[category]}</h4>
        <dl>
          <div><dt>Finding ID</dt><dd><code>{selected.finding_id}</code></dd></div>
          {localFinding && <div><dt>규칙과 위치</dt><dd><code>{localFinding.rule_id}</code> · {localFinding.file_path ?? '파일 위치 확인 불가'}{localFinding.line_number ? `:${localFinding.line_number}` : ''}</dd></div>}
          {selected.path_observation && <div><dt>현재 경로 관찰</dt><dd>{investigationPathLabels[selected.path_observation]}</dd></div>}
          {selected.skip_hypothesis && <div><dt>경로 제외 가설</dt><dd>{investigationAssessmentLabels[selected.skip_hypothesis]}</dd></div>}
          {selected.source_snapshot_hypothesis && <div><dt>코드 변경 가설</dt><dd>{investigationAssessmentLabels[selected.source_snapshot_hypothesis]}</dd></div>}
          {selected.rule_identity_hypothesis && <div><dt>규칙 동일성 가설</dt><dd>{investigationAssessmentLabels[selected.rule_identity_hypothesis]}</dd></div>}
        </dl>
      </div> : <p className="investigation-guidance">이 범주에 해당하는 Finding이 없습니다.</p>}
      {evaluation.limitation_codes.length > 0 && <details className="investigation-limitations"><summary>분석 한계 확인 ({evaluation.limitation_codes.length})</summary><ul>{evaluation.limitation_codes.map((code) => <li key={code}>{investigationLimitationLabels[code]}</li>)}</ul></details>}
    </div>}
  </section>;
}

function ComparisonContext({label, snapshot}:{label:string; snapshot:ScanSnapshot|null}) {
  return <div>
    <strong>{label}</strong>
    {snapshot ? <>
      <span>{receivedAtLabel(snapshot.context.receivedAt)}</span>
      <span>{snapshot.context.targetLabel} · {snapshot.context.ruleProfileLabel}{snapshot.context.experimental ? ' · Experimental' : ''}</span>
      <span>Semgrep {snapshot.scan.semgrep_version ?? '버전 확인 불가'} · {statusLabels[snapshot.scan.scan_status]}</span>
    </> : <span>{label === '기준 검사' ? '지정되지 않음' : '아직 없음'}</span>}
  </div>;
}
