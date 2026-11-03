import type { ApiFinding } from '../../api/types';
import type { ScanComparison, ScanSnapshot } from './compare';
import type { FindingTriage, ScanTriage } from './findingTriage';

export type RescanObservationCategory = 'currentOnly' | 'shared' | 'baselineOnly';
export type ComparableFindingMetadata =
  | 'rule_id' | 'file_path' | 'line_number' | 'severity' | 'finding_kind'
  | 'evidence_validation_status' | 'verification_status';

export interface RescanFollowupItem {
  category: RescanObservationCategory;
  findingId: string;
  finding: ApiFinding;
  baselineFinding: ApiFinding | null;
  currentFinding: ApiFinding | null;
  canOpenCurrentFinding: boolean;
  tasks: readonly string[];
  limitation: string;
  changedMetadata: readonly ComparableFindingMetadata[];
  metadataSummary: string | null;
  triage: FindingTriage | null;
}

export interface RescanFollowup {
  comparable: boolean;
  groups: Record<RescanObservationCategory, RescanFollowupItem[]>;
}

const tasks: Record<RescanObservationCategory, readonly string[]> = {
  currentOnly: [
    '현재 탐지 위치와 규칙 ID를 확인합니다.',
    '기준 검사와 관찰 결과가 달라진 원인을 검토합니다.',
    '코드·파일·규칙 위치가 바뀌었을 가능성을 확인합니다.',
    '현재 코드에서 실제 위험 여부와 실행 조건을 검토합니다.',
    '현재 Finding 상세의 분석가 검토 가이드를 확인합니다.',
  ],
  shared: [
    '현재 Finding의 코드 위치를 확인합니다.',
    '현재 근거 연결 상태와 취약점 검증 상태를 확인합니다.',
    '기준 검사와 현재 검사의 응답 메타데이터를 비교합니다.',
    '이전 검토 결과와 무관하게 현재 코드를 다시 확인합니다.',
    '필요하면 현재 검사에 수동 검토 상태와 메모를 기록합니다.',
  ],
  baselineOnly: [
    '기준 검사에서 보고된 탐지 위치를 확인합니다.',
    '현재 코드에서 해당 위치와 주변 코드를 확인합니다.',
    '코드 이동 또는 규칙 매치 변화 가능성을 확인합니다.',
    '실제 코드 변경 여부를 별도로 검토합니다.',
    '필요하면 다시 검사하거나 원본 프로젝트를 수동 검토합니다.',
  ],
};

const limitations: Record<RescanObservationCategory, string> = {
  currentOnly: '이번 검사에서만 관찰됐다는 사실은 새로운 취약점이 발생했다는 증거가 아닙니다.',
  shared: '동일 Finding ID가 유지돼도 코드 내용과 실제 보안 상태가 동일하다는 뜻은 아닙니다.',
  baselineOnly: '현재 검사에서 관찰되지 않는다는 사실은 취약점 수정이나 해결 완료의 증거가 아닙니다.',
};

const metadataFields: readonly ComparableFindingMetadata[] = [
  'rule_id', 'file_path', 'line_number', 'severity', 'finding_kind',
  'evidence_validation_status', 'verification_status',
];

function metadataChanges(baseline: ApiFinding, current: ApiFinding): ComparableFindingMetadata[] {
  return metadataFields.filter((field) => baseline[field] !== current[field]);
}

function item(
  category: RescanObservationCategory,
  finding: ApiFinding,
  baselineFinding: ApiFinding | null,
  currentFinding: ApiFinding | null,
  triage: FindingTriage | null,
): RescanFollowupItem {
  const changedMetadata = baselineFinding && currentFinding ? metadataChanges(baselineFinding, currentFinding) : [];
  const metadataSummary = category !== 'shared' ? null : changedMetadata.length
    ? `비교 가능한 응답 메타데이터에서 차이가 관찰됐습니다: ${changedMetadata.join(', ')}. 이 차이만으로 코드 변경이나 보안 상태 변화를 확정할 수 없습니다.`
    : '비교 가능한 응답 메타데이터에서 차이가 관찰되지 않았습니다. 코드 내용이나 실제 보안 상태의 동일성을 뜻하지 않습니다.';
  return {
    category,
    findingId: finding.finding_id,
    finding,
    baselineFinding,
    currentFinding,
    canOpenCurrentFinding: currentFinding !== null,
    tasks: [...tasks[category]],
    limitation: limitations[category],
    changedMetadata,
    metadataSummary,
    triage,
  };
}

const emptyGroups = (): RescanFollowup['groups'] => ({ currentOnly: [], shared: [], baselineOnly: [] });

/** Add deterministic analyst follow-up work to an already validated Phase 8A comparison. */
export function createRescanFollowup(
  comparison: ScanComparison,
  baseline: ScanSnapshot | null,
  current: ScanSnapshot | null,
  currentTriage: ScanTriage | null,
): RescanFollowup {
  if (!comparison.comparable || !comparison.groups || !baseline || !current) {
    return { comparable: false, groups: emptyGroups() };
  }
  const baselineById = new Map(baseline.scan.findings.map((finding) => [finding.finding_id, finding]));
  const currentById = new Map(current.scan.findings.map((finding) => [finding.finding_id, finding]));
  const triageById = new Map((currentTriage?.findings ?? []).map((entry) => [entry.findingId, entry]));
  return {
    comparable: true,
    groups: {
      currentOnly: comparison.groups.currentOnly.map((finding) => item(
        'currentOnly', finding, null, finding, triageById.get(finding.finding_id) ?? null,
      )),
      shared: comparison.groups.shared.map((finding) => item(
        'shared', finding, baselineById.get(finding.finding_id) ?? null,
        currentById.get(finding.finding_id) ?? null, triageById.get(finding.finding_id) ?? null,
      )),
      baselineOnly: comparison.groups.baselineOnly.map((finding) => item(
        'baselineOnly', finding, finding, null, null,
      )),
    },
  };
}
