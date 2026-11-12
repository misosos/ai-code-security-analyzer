import { parseScan, type ScanResponse } from '../../api/types';
import type { ScanContext } from './markdownExport';
import { createSarifReport, type SarifReport } from './sarifExport';

export type PreflightStatus = 'VERIFIED' | 'REQUIRES_VERIFICATION' | 'UNSUPPORTED' | 'BLOCKED';
export type FindingLocationState = 'FILE_AND_LINE' | 'FILE_WITHOUT_LINE' | 'NO_FILE_OR_LINE';

export interface PreflightCheck {
  status: PreflightStatus;
  summary: string;
  detail: string;
}

export interface FindingLocationCheck {
  findingId: string;
  ruleId: string;
  state: FindingLocationState;
  uriFormat: PreflightStatus;
  repositoryFile: PreflightStatus;
  uri?: string;
  lineNumber?: number;
}

export interface CodeScanningPreflight {
  checks: {
    sarifStructure: PreflightCheck;
    ruleReferences: PreflightCheck;
    ruleStability: PreflightCheck;
    pathFormat: PreflightCheck;
    remoteRepository: PreflightCheck;
    repositoryCommit: PreflightCheck;
    sourceSnapshot: PreflightCheck;
    fingerprints: PreflightCheck;
    scanScope: PreflightCheck;
    workflowPermissions: PreflightCheck;
    trustBoundary: PreflightCheck;
  };
  findingLocations: FindingLocationCheck[];
  resultCount: number;
  omittedFindingCount: number;
  uploadReadiness: 'REQUIRES_VERIFICATION' | 'BLOCKED';
  uploadMethods: { uploadSarifAction: PreflightStatus; restApi: PreflightStatus };
  githubUploadPerformed: false;
  scopeMessage: string;
  requiredBeforeUpload: string[];
}

const verified = (summary: string, detail: string): PreflightCheck => ({ status: 'VERIFIED', summary, detail });
const requires = (summary: string, detail: string): PreflightCheck => ({ status: 'REQUIRES_VERIFICATION', summary, detail });
const unsupported = (summary: string, detail: string): PreflightCheck => ({ status: 'UNSUPPORTED', summary, detail });
const blocked = (summary: string, detail: string): PreflightCheck => ({ status: 'BLOCKED', summary, detail });

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateGeneratedSarif(scan: ScanResponse, context: ScanContext, value: unknown): value is SarifReport {
  if (!isPlainRecord(value) || value.version !== '2.1.0' || typeof value.$schema !== 'string'
    || !Array.isArray(value.runs) || value.runs.length !== 1) return false;
  const run = value.runs[0];
  if (!isPlainRecord(run) || !isPlainRecord(run.tool) || !isPlainRecord(run.tool.driver)
    || run.tool.driver.name !== 'SAST Review Workspace'
    || !Array.isArray(run.tool.driver.rules) || !Array.isArray(run.results)
    || !Array.isArray(run.invocations) || run.invocations.length !== 1
    || !isPlainRecord(run.properties)) return false;

  const expected = createSarifReport(context, scan);
  try {
    // This is a closed local producer contract, not a general SARIF file parser.
    // Full OASIS validation of this producer is exercised against the pinned schema in tests.
    return JSON.stringify(value) === JSON.stringify(expected);
  } catch {
    return false;
  }
}

function locationChecks(scan: ScanResponse, report: SarifReport): FindingLocationCheck[] {
  const resultsById = new Map(report.runs[0].results.map((result) => [
    String(result.properties.aiCodeSecurityAnalyzerFindingId), result,
  ]));
  return scan.findings.map((finding) => {
    const result = resultsById.get(finding.finding_id);
    const uri = result?.locations?.[0]?.physicalLocation.artifactLocation.uri;
    const state: FindingLocationState = finding.file_path === null
      ? 'NO_FILE_OR_LINE'
      : finding.line_number === null ? 'FILE_WITHOUT_LINE' : 'FILE_AND_LINE';
    return {
      findingId: finding.finding_id,
      ruleId: finding.rule_id,
      state,
      uriFormat: state === 'NO_FILE_OR_LINE' ? 'REQUIRES_VERIFICATION'
        : typeof uri === 'string' && uri.length > 0 && !uri.startsWith('/') && !uri.includes('\\') && !uri.split('/').some((part) => part === '.' || part === '..')
          ? 'VERIFIED' : 'BLOCKED',
      repositoryFile: 'REQUIRES_VERIFICATION',
      ...(typeof uri === 'string' ? { uri } : {}),
      ...(finding.line_number !== null ? { lineNumber: finding.line_number } : {}),
    };
  });
}

export function createCodeScanningPreflight(
  input: ScanResponse,
  context: ScanContext,
  sarif: unknown,
): CodeScanningPreflight {
  let scan: ScanResponse;
  try {
    scan = parseScan(input);
  } catch {
    throw new Error('preflight_scan_invalid');
  }
  if (!context || typeof context !== 'object' || context.scanStatus !== scan.scan_status
    || typeof context.targetId !== 'string' || typeof context.ruleProfileId !== 'string') {
    throw new Error('preflight_context_mismatch');
  }

  const structurallyValid = validateGeneratedSarif(scan, context, sarif);
  const report = structurallyValid ? sarif : createSarifReport(context, scan);
  const findings = [...scan.findings].sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  const resultsById = new Map(report.runs[0].results.map((result) => [
    String(result.properties.aiCodeSecurityAnalyzerFindingId), result,
  ]));
  const descriptors = new Map(report.runs[0].tool.driver.rules.map((rule, index) => [rule.id, index]));
  const referencesValid = structurallyValid
    && report.runs[0].results.length === scan.displayed_finding_count
    && findings.every((finding) => {
      const result = resultsById.get(finding.finding_id);
      return result?.ruleId === finding.rule_id
        && result.ruleIndex === descriptors.get(result.ruleId)
        && result.properties.originalSeverity === finding.severity;
    });
  const scopeIsFull = scan.scan_status === 'completed' && scan.completed
    && scan.omitted_finding_count === 0 && scan.displayed_finding_count === scan.finding_count;
  const scopeIsRepresented = scan.displayed_finding_count === scan.findings.length
    && scan.finding_count === scan.displayed_finding_count + scan.omitted_finding_count;
  const paths = structurallyValid ? locationChecks(scan, report) : [];
  const pathsValid = structurallyValid && paths.every((item) => item.uriFormat !== 'BLOCKED');
  const checkScope = scopeIsFull && referencesValid
    ? verified('완료 응답의 Finding 전체가 SARIF에 포함됨', '이는 API 응답의 표현이 완전하다는 뜻이며, 분석기가 모든 문제를 발견했다는 보장은 아닙니다.')
    : blocked('업로드 전 검사 범위 확인 필요', scan.omitted_finding_count > 0
      ? `Finding ${scan.omitted_finding_count}건이 생략되어 현재 SARIF는 일부 응답만 포함합니다.`
      : '검사가 정상 완료되지 않았거나 SARIF 결과와 API 응답의 개수가 일치하지 않습니다.');

  const checks: CodeScanningPreflight['checks'] = {
    sarifStructure: structurallyValid
      ? verified('SARIF 2.1.0 생성 구조 확인', '현재 SARIF 생성기 출력은 고정된 OASIS 스키마 기반 회귀 테스트로 검증됩니다.')
      : blocked('SARIF 구조 또는 생성기 일치 확인 실패', '현재 검증된 검사 응답에서 생성한 SARIF와 전달된 결과가 일치하지 않습니다.'),
    ruleReferences: referencesValid
      ? verified('Rule ID와 ruleIndex 연결 확인', '모든 결과의 Rule ID가 하나의 reporting descriptor와 일치합니다.')
      : blocked('Rule 참조 불일치', '결과 수, Rule ID 또는 ruleIndex가 현재 API 응답과 일치하지 않습니다.'),
    ruleStability: requires('여러 분석 실행 간 Rule ID 안정성 미확인', '현재 실행 안의 참조만 확인했습니다. 향후 rule ID가 변경되지 않는지는 규칙 릴리스 정책과 이전 실행 기록으로 확인해야 합니다.'),
    pathFormat: pathsValid
      ? verified('SARIF 경로 형식 확인', '제공된 위치는 상대 URI 형식이며 URI 구분 문자는 인코딩됐습니다.')
      : blocked('SARIF 경로 형식 검증 실패', '위치 URI가 안전한 상대 경로 형식이 아니거나 결과와 일치하지 않습니다.'),
    remoteRepository: requires('원격 저장소 파일 일치 미확인', '로컬 target ID는 GitHub 저장소와의 동일성을 증명하지 않습니다. 원격 저장소의 파일 존재와 상대 경로를 확인해야 합니다.'),
    repositoryCommit: requires('Git commit / ref 연결 미확인', 'API 응답은 검사된 소스를 특정 commit 또는 branch와 연결하지 않습니다.'),
    sourceSnapshot: requires('분석 당시 소스 스냅샷 미확인', '코드 스냅샷이나 행 내용이 제공되지 않아 현재 저장소 내용과 같은지 확인할 수 없습니다.'),
    fingerprints: unsupported('안정적인 Fingerprint 미지원', 'Finding ID는 분석기 내부 식별자이며 코드 행 fingerprint가 아닙니다. 현재 SARIF에 fingerprint를 만들지 않았으므로 중복 경고 위험과 보완 방식은 업로드 경로에서 검증해야 합니다.'),
    scanScope: scopeIsRepresented ? checkScope : blocked('검사 범위 데이터 불일치', 'Finding 개수와 API 응답의 개수가 일치하지 않습니다.'),
    workflowPermissions: requires('업로드 권한 및 저장소 정책 미확인', 'Code Scanning 사용 가능 여부와 대상 저장소의 security-events 쓰기 권한이 확인되지 않았습니다.'),
    trustBoundary: requires('업로드 Workflow 신뢰 경계 미검증', '외부 기여 코드 실행 이후 쓰기 토큰을 사용하는 안전성은 별도의 Workflow 설계와 위협 검토가 필요합니다.'),
  };

  const blocking = !structurallyValid || !referencesValid || !pathsValid || !scopeIsRepresented || !scopeIsFull;
  return {
    checks,
    findingLocations: paths,
    resultCount: structurallyValid ? report.runs[0].results.length : 0,
    omittedFindingCount: scan.omitted_finding_count,
    uploadReadiness: blocking ? 'BLOCKED' : 'REQUIRES_VERIFICATION',
    uploadMethods: { uploadSarifAction: 'REQUIRES_VERIFICATION', restApi: 'REQUIRES_VERIFICATION' },
    githubUploadPerformed: false,
    scopeMessage: scan.finding_count === 0 && scan.scan_status === 'completed'
      ? '현재 응답에서 Finding이 보고되지 않았습니다. 이는 저장소가 안전하다는 증명이 아닙니다.'
      : checkScope.detail,
    requiredBeforeUpload: [
      '대상 GitHub 저장소에서 Code Scanning을 사용할 수 있는지 확인',
      'SARIF 경로가 업로드 대상 commit의 파일과 일치하는지 확인',
      'Rule ID와 분석 category를 여러 실행에서 안정적으로 유지할지 확인',
      'fingerprint가 없는 경우 upload-sarif 보완과 REST API 중복 위험을 검토',
      'PR / fork 코드 실행과 security-events: write 권한의 신뢰 경계를 검토',
      '부분 검사 또는 생략 Finding 결과를 업로드할지 명시적으로 결정',
    ],
  };
}
