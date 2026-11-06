import { parseInvestigationEvaluation, parseRuleBytesComparison, type InvestigationAssessment, type InvestigationPathObservation, type RuleBytesComparison } from '../../api/investigation';
import { compareScanSnapshots, type ScanComparison } from './compare';
import { evidenceDisplayExpired, validateInvestigationContext, type EvidenceBackedScan } from './investigationWorkflow';

export type GapStatus = 'OBSERVED' | 'NOT_REPORTED' | 'NOT_COLLECTED' | 'UNAVAILABLE' | 'UNVERIFIED' | 'INCOMPARABLE' | 'CONFLICTING' | 'NOT_APPLICABLE';
export interface GapEntry { id: string; status: GapStatus; fact: string; source: string; unknown: string; followUp?: string }
export interface FindingGap { findingId: string; ruleId: string; path: string | null; pathEvidence: GapEntry; skipHypothesis: InvestigationAssessment | null }
export interface EvidenceGapMap { entries: GapEntry[]; findings: FindingGap[]; actions: string[] }

const paths: Record<InvestigationPathObservation, Omit<GapEntry, 'id' | 'source'>> = {
  PATH_REPORTED_SCANNED: { status: 'OBSERVED', fact: 'Semgrep이 이 경로를 처리 대상으로 보고했습니다.', unknown: '모든 규칙의 적용 완료는 확인되지 않았습니다.' },
  PATH_EXPLICITLY_SKIPPED: { status: 'OBSERVED', fact: '현재 검사에서 이 경로가 제외됐다고 보고됐습니다.', unknown: '구체적인 제외 사유와 취약점 해결 여부는 이 관찰만으로 확인되지 않습니다.', followUp: '해당 상대 경로의 Ignore 설정 및 파일 포함 여부를 확인한 뒤 포함되는 조건에서 재검사하세요.' },
  PATH_NOT_REPORTED: { status: 'NOT_REPORTED', fact: '수집된 경로 목록에서 이 경로가 보고되지 않았습니다.', unknown: '제외, 삭제 또는 수정 여부는 확인되지 않았습니다.', followUp: '대상 경로와 검사 설정을 확인하세요.' },
  SKIP_EVIDENCE_NOT_COLLECTED: { status: 'NOT_COLLECTED', fact: '경로 제외 상세는 수집되지 않았습니다.', unknown: '실제 제외 여부는 확인되지 않았습니다.', followUp: '해당 상대 경로의 Ignore 설정 및 파일 포함 여부를 확인하세요.' },
  SCOPE_EVIDENCE_UNAVAILABLE: { status: 'UNAVAILABLE', fact: '경로 증거를 사용할 수 없습니다.', unknown: '경로 처리 여부는 확인되지 않았습니다.', followUp: '검사 오류와 대상 설정을 확인하세요.' },
  FINDING_PATH_UNAVAILABLE: { status: 'UNAVAILABLE', fact: '기준 Finding의 경로를 사용할 수 없습니다.', unknown: '해당 경로의 처리 여부는 확인되지 않았습니다.' },
  CONFLICTING: { status: 'CONFLICTING', fact: '경로 증거가 충돌합니다.', unknown: '경로 처리 여부를 확정할 수 없습니다.', followUp: '검사 설정과 오류를 확인하세요.' },
};

/** Construct only from the current session's parsed, bound DTOs. No handles enter the result. */
export function createEvidenceGapMap(
  baseline: EvidenceBackedScan | null, current: EvidenceBackedScan | null,
  rawEvaluation: unknown, rawRuleComparison: unknown | null, comparison: ScanComparison,
): EvidenceGapMap | null {
  try {
    const evaluation = parseInvestigationEvaluation(rawEvaluation);
    if (!['COMPARABLE', 'INCOMPARABLE'].includes(evaluation.comparability)
      || (evaluation.comparability === 'INCOMPARABLE' && evaluation.overall_assessment !== 'INCOMPARABLE')
      || (evaluation.comparability === 'COMPARABLE' && !['UNDETERMINED', 'EXPLANATION_SUPPORTED', 'MULTIPLE_EXPLANATIONS_POSSIBLE'].includes(evaluation.overall_assessment))) return null;
    for (const item of evaluation.findings.filter((finding) => finding.category === 'baselineOnly')) {
      if (!item.path_observation) return null;
      const expectedSkip = item.path_observation === 'PATH_EXPLICITLY_SKIPPED' ? 'SUPPORTED'
        : item.path_observation === 'PATH_REPORTED_SCANNED' ? 'CONTRADICTED'
          : item.path_observation === 'CONFLICTING' ? 'INCOMPARABLE' : 'UNDETERMINED';
      if (item.skip_hypothesis !== expectedSkip || item.source_snapshot_hypothesis !== 'UNDETERMINED'
        || item.rule_identity_hypothesis !== 'UNDETERMINED') return null;
    }
    if (!baseline || !current || evidenceDisplayExpired(baseline, performance.now()) || evidenceDisplayExpired(current, performance.now())) return null;
    const checkedComparison = compareScanSnapshots(baseline.snapshot, current.snapshot);
    if (comparison.comparable !== checkedComparison.comparable
      || comparison.reasons.join('|') !== checkedComparison.reasons.join('|')
      || !validateInvestigationContext(baseline, current, evaluation, checkedComparison).valid) return null;
    const ruleMode = (baseline.evidenceMode ?? 'standard') === 'rule-bytes';
    if (ruleMode && rawRuleComparison === null) return null;
    if (!ruleMode && rawRuleComparison !== null) return null;
    const rule: RuleBytesComparison | null = ruleMode ? parseRuleBytesComparison(rawRuleComparison) : null;
    if (rule && (!baseline.snapshot.scan.completed || !current.snapshot.scan.completed)
      && (rule.status === 'SAME_SELECTED_BYTES' || rule.status === 'DIFFERENT_SELECTED_BYTES')) return null;
    const entries: GapEntry[] = [];
    if (evaluation.comparability === 'INCOMPARABLE') entries.push({ id: 'comparison', status: 'INCOMPARABLE', fact: '서버 평가가 두 검사를 비교 불가로 보고했습니다.', source: 'Evaluation v1', unknown: '정상 완료 검사로 비교할 수 없습니다.', followUp: '검사 상태와 오류를 확인하고 동일 조건의 완료된 검사를 확보하세요.' });
    const counts = { baselineOnly: 0, shared: 0, currentOnly: 0 };
    for (const finding of evaluation.findings) counts[finding.category] += 1;
    entries.push({ id: 'finding-change', status: 'OBSERVED', fact: `기준만 ${counts.baselineOnly}건 · 양쪽 ${counts.shared}건 · 현재만 ${counts.currentOnly}건`, source: 'Evaluation v1 및 검사 응답', unknown: 'Finding ID의 일치나 차이는 코드 또는 취약점의 의미상 동일성을 증명하지 않습니다.' });
    const ruleEntry: GapEntry = { id: 'rule-bytes', source: 'Rule Bytes Comparison v1', status: 'NOT_APPLICABLE', fact: '규칙 바이트 비교를 요청하지 않았습니다.', unknown: '선택 규칙 파일의 바이트 동일성은 확인되지 않았습니다.' };
    if (rule) {
      const values: Record<RuleBytesComparison['status'], Pick<GapEntry, 'status' | 'fact'>> = {
        SAME_SELECTED_BYTES: { status: 'OBSERVED', fact: '두 실행에 제공한 선택된 단일 규칙 파일 사본의 바이트가 같습니다.' },
        DIFFERENT_SELECTED_BYTES: { status: 'OBSERVED', fact: '두 실행에 제공한 선택된 단일 규칙 파일 사본의 바이트가 다릅니다. 주석 변경도 차이를 만듭니다.' },
        UNVERIFIED: { status: 'UNVERIFIED', fact: '선택 규칙 파일 바이트 비교 근거가 부족합니다.' },
        INCOMPARABLE: { status: 'INCOMPARABLE', fact: '선택 규칙 파일 바이트를 비교할 수 없습니다.' },
      };
      Object.assign(ruleEntry, values[rule.status]);
      ruleEntry.unknown = '전체 로딩 규칙의 동일성이나 Finding 변화의 원인은 확인되지 않았습니다.';
      if (rule.status === 'DIFFERENT_SELECTED_BYTES') ruleEntry.followUp = '선택 규칙 파일과 변경 기록을 별도로 확인하세요.';
    } else ruleEntry.source = '조사 옵션';
    entries.push(ruleEntry);
    const limitations = new Set(evaluation.limitation_codes);
    if (limitations.has('rule_bytes_unverified')) entries.push({ id: 'evaluation-rule-scope', status: 'UNVERIFIED', fact: '기존 Evaluation v1은 규칙 바이트를 검증하지 않습니다.', source: 'Evaluation v1', unknown: '별도 Rule Bytes 비교는 선택된 단일 파일 사본에만 적용됩니다.' });
    if (limitations.has('source_snapshot_not_collected')) entries.push({ id: 'source', status: 'NOT_COLLECTED', fact: '소스 스냅샷을 수집하지 않았습니다.', source: 'Evaluation v1', unknown: '검사 시점의 소스 코드 바이트 변경 여부를 확인할 수 없습니다.', followUp: '별도의 Git Diff 또는 승인된 소스 변경 기록을 확인하세요.' });
    if (limitations.has('loaded_rule_identity_unverified')) entries.push({ id: 'loaded-rules', status: 'UNVERIFIED', fact: '전체 로딩 규칙 동일성은 검증되지 않았습니다.', source: 'Evaluation v1', unknown: 'Semgrep이 실제로 로딩한 전체 규칙 집합의 동일성은 확인되지 않았습니다.', followUp: '규칙 구성과 실행 환경을 별도로 확인하세요.' });
    if (limitations.has('scope_completeness_unverified')) entries.push({ id: 'scope', status: 'UNVERIFIED', fact: '전체 검사 범위의 완전성은 검증되지 않았습니다.', source: 'Evaluation v1', unknown: '경로 처리 보고는 모든 규칙의 분석 완료를 뜻하지 않습니다.', followUp: '대상 범위, 제외 설정과 검사 오류를 확인하세요.' });
    entries.push({ id: 'resolution', status: 'UNVERIFIED', fact: '취약점 해결 여부는 이 조사만으로 판정할 수 없습니다.', source: '정적 검사 제한', unknown: '실제 영향과 해결 여부에는 별도의 검토가 필요합니다.', followUp: '실제 영향과 수정 여부를 별도로 검토하세요.' });
    const findings = evaluation.findings.filter((item) => item.category === 'baselineOnly').map((item): FindingGap => {
      const local = baseline.snapshot.scan.findings.find((finding) => finding.finding_id === item.finding_id)!;
      const observation = item.path_observation;
      const pathEvidence: GapEntry = observation ? { id: 'path', source: 'Evaluation v1 · Finding별 경로 관찰', ...paths[observation] }
        : { id: 'path', source: 'Evaluation v1', status: 'NOT_APPLICABLE', fact: '이 Finding에 대한 경로 관찰이 제공되지 않았습니다.', unknown: '경로 처리 여부는 확인되지 않았습니다.' };
      if (observation === 'PATH_EXPLICITLY_SKIPPED' && item.skip_hypothesis === 'SUPPORTED') pathEvidence.fact += ' 경로 제외 가설을 뒷받침하는 절차상 관찰입니다.';
      return { findingId: item.finding_id, ruleId: local.rule_id, path: local.file_path, pathEvidence, skipHypothesis: item.skip_hypothesis };
    }).sort((a, b) => a.findingId.localeCompare(b.findingId));
    const actions = [...entries.filter((e) => e.id === 'comparison').map((e) => e.followUp), ...findings.map((f) => f.pathEvidence.followUp), ...entries.filter((e) => e.id !== 'comparison').map((e) => e.followUp)].filter((v): v is string => Boolean(v));
    return { entries, findings, actions: [...new Set(actions)] };
  } catch { return null; }
}
