import type { InvestigationAssessment, InvestigationLimitationCode, InvestigationPathObservation } from '../../api/investigation';

export const investigationAssessmentLabels: Record<InvestigationAssessment, string> = {
  COMPARABLE: '비교 가능한 관찰',
  SUPPORTED: '해당 가설을 뒷받침하는 근거 관찰',
  CONTRADICTED: '해당 가설과 다른 근거 관찰',
  UNDETERMINED: '현재 증거로 판단 불가',
  INCOMPARABLE: '신뢰 가능한 비교 불가',
  EXPLANATION_SUPPORTED: '검사 절차 설명을 뒷받침하는 근거 있음',
  MULTIPLE_EXPLANATIONS_POSSIBLE: '여러 설명이 가능함',
};

export const investigationPathLabels: Record<InvestigationPathObservation, string> = {
  PATH_REPORTED_SCANNED: '현재 Semgrep이 이 경로를 처리 대상으로 보고했습니다. 모든 규칙의 분석 완료를 의미하지는 않습니다.',
  PATH_EXPLICITLY_SKIPPED: '현재 검사에서 해당 경로가 제외된 것으로 보고됐습니다. 이는 검사 절차의 관찰이며 취약점 해결을 의미하지 않습니다.',
  PATH_NOT_REPORTED: '현재 수집된 검사 경로 목록에서 이 경로가 보고되지 않았습니다. 제외·삭제·수정을 확정할 수 없습니다.',
  SKIP_EVIDENCE_NOT_COLLECTED: '경로 제외 정보를 수집하지 못했습니다. 실제 제외 여부를 판단할 수 없습니다.',
  SCOPE_EVIDENCE_UNAVAILABLE: '검사 범위 증거를 사용할 수 없습니다.',
  FINDING_PATH_UNAVAILABLE: '기준 Finding에 비교할 파일 경로가 없습니다.',
  CONFLICTING: '검사 범위 자료가 서로 충돌해 경로 관찰을 확정할 수 없습니다.',
};

export const investigationLimitationLabels: Record<InvestigationLimitationCode, string> = {
  scan_context_mismatch: '검사 문맥이 달라 비교할 수 없습니다.',
  scan_reference_collision: '검사 실행 식별자가 충돌했습니다.',
  manifest_binding_invalid: '검사 증거 연결을 검증할 수 없습니다.',
  response_manifest_binding_invalid: '검사 응답과 증거의 연결이 일치하지 않습니다.',
  duplicate_finding_id: '중복 Finding ID가 있어 평가를 제한했습니다.',
  finding_id_not_observed: 'Finding ID 기준의 관찰 차이만 표시합니다. 의미상 동일성을 뜻하지 않습니다.',
  scan_incomplete: '하나 이상의 검사가 완료되지 않았습니다.',
  finding_omitted: '응답에서 Finding이 생략되어 결과가 불완전합니다.',
  rule_bytes_unverified: '검사 시점의 규칙 파일 내용은 검증되지 않았습니다.',
  loaded_rule_identity_unverified: '엔진에 실제 로딩된 전체 규칙 집합은 검증되지 않았습니다.',
  source_snapshot_not_collected: '검사 시점의 일반 소스 코드 스냅샷을 수집하지 않았습니다.',
  scope_completeness_unverified: '보고된 처리 경로가 전체 검사 범위를 증명하지는 않습니다.',
  path_reported_scanned: 'Semgrep이 처리 경로로 보고한 관찰입니다. 모든 규칙의 분석 완료 증거는 아닙니다.',
  path_explicitly_skipped: '검사에서 경로가 제외됐다는 절차상 관찰입니다. 취약점 해결 증거는 아닙니다.',
  path_not_reported: '경로가 수집된 목록에 없다는 사실만으로 제외 여부를 알 수 없습니다.',
  skip_details_not_collected: '경로 제외 사유를 수집하지 않았습니다.',
  scope_evidence_unavailable: '검사 범위 증거를 사용할 수 없습니다.',
  finding_path_unavailable: 'Finding 파일 경로를 확인할 수 없습니다.',
  scanned_skipped_path_conflict: '같은 경로가 처리·제외 목록에 모두 보고됐습니다.',
  evaluation_output_limit_exceeded: '평가 결과 제한을 초과했습니다.',
  scan_result_is_not_safety_proof: 'Finding이 관찰되지 않아도 코드 안전성이나 취약점 해결을 증명하지 않습니다.',
};

export function investigationErrorMessage(status: number, code: string): string {
  if (code === 'unauthorized' || status === 401) return '토큰을 확인하세요. 조사 요청이 인증되지 않았습니다.';
  if (code === 'host_not_allowed') return '요청 Host가 로컬 API 허용 목록에 없습니다.';
  if (code === 'origin_not_allowed' || status === 403) return '브라우저 출처가 서버 허용 목록에 없습니다. 서버의 Origin 설정을 확인하세요.';
  if (code === 'unsupported_deployment') return '조사 API를 사용할 수 없습니다. 공식 단일 Worker 실행이 필요합니다. 일반 검사로 바꾸려면 검사 방식에서 직접 선택하세요.';
  if (code === 'evidence_unavailable' || status === 404) return '조사 증거가 만료되었거나 사용할 수 없습니다. 조사 모드에서 새 기준 검사를 실행하세요.';
  if (code === 'evaluation_busy') return '다른 증거 평가가 진행 중입니다. 잠시 뒤 다시 시도하세요.';
  if (code === 'binding_rejected' || status === 409) return '검사 문맥이 일치하지 않아 조사를 차단했습니다.';
  if (code === 'resource_limit' || status === 429) return '조사 요청 또는 임시 서버 용량 제한에 도달했습니다. 잠시 후 다시 시도하세요.';
  if (code === 'invalid_content_type') return '조사 요청 형식을 확인하지 못했습니다.';
  if (code === 'response_limit_exceeded') return '조사 응답이 허용 크기를 초과해 결과를 표시하지 않았습니다.';
  if (code === 'request_cancelled') return '조사 요청이 중단되어 증거를 사용할 수 없습니다. 다시 검사하세요.';
  if (code === 'invalid_request' || code === 'invalid_api_response') return '요청 또는 응답 검증에 실패했습니다. 결과를 표시하지 않았습니다.';
  if (code === 'connection_error' || status === 0) return '로컬 API에 연결할 수 없습니다. 조사 결과는 확인되지 않았습니다.';
  return '조사 증거 처리에 실패했습니다. 서버 응답의 세부 내용은 표시하지 않습니다.';
}
