import { describe, expect, it } from 'vitest';
import {
  investigationAssessmentLabels,
  investigationLimitationLabels,
  investigationPathLabels,
} from '../src/features/scans/investigationMessages';

describe('investigation acceptance language', () => {
  it('covers every evidence state with bounded Korean guidance', () => {
    expect(Object.keys(investigationPathLabels).sort()).toEqual([
      'CONFLICTING',
      'FINDING_PATH_UNAVAILABLE',
      'PATH_EXPLICITLY_SKIPPED',
      'PATH_NOT_REPORTED',
      'PATH_REPORTED_SCANNED',
      'SCOPE_EVIDENCE_UNAVAILABLE',
      'SKIP_EVIDENCE_NOT_COLLECTED',
    ]);
    expect(investigationAssessmentLabels.UNDETERMINED).toContain('판단 불가');
    expect(investigationAssessmentLabels.INCOMPARABLE).toContain('비교 불가');
    expect(investigationPathLabels.PATH_REPORTED_SCANNED).toContain('모든 규칙의 분석 완료를 의미하지는 않습니다');
    expect(investigationPathLabels.PATH_EXPLICITLY_SKIPPED).toContain('취약점 해결을 의미하지 않습니다');
    expect(investigationPathLabels.PATH_NOT_REPORTED).toContain('확정할 수 없습니다');
  });

  it('does not turn an evidence observation or limitation into a remediation claim', () => {
    const renderedCatalog = [
      ...Object.values(investigationAssessmentLabels),
      ...Object.values(investigationPathLabels),
      ...Object.values(investigationLimitationLabels),
    ].join('\n');
    for (const forbidden of ['취약점 해결 완료', '자동 수정 확인', '안전성 검증 완료', '취약점이 제거됨', '코드가 안전해짐']) {
      expect(renderedCatalog).not.toContain(forbidden);
    }
    expect(renderedCatalog).toContain('코드 안전성이나 취약점 해결을 증명하지 않습니다');
  });
});
