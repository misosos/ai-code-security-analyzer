import { describe, expect, it } from 'vitest';
import { describeStatusCode } from '../src/app/BeginnerGuidance';

const documentedCodes = [
  'semgrep_not_installed', 'semgrep_timeout', 'semgrep_output_limit', 'invalid_json',
  'semgrep_failed', 'findings_omitted', 'evidence_unavailable',
  'finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof',
  'scan_partial', 'scan_failed', 'omitted_findings_not_individually_validated',
];

describe('beginner scan status explanations', () => {
  it.each(documentedCodes)('provides a plain-language title, explanation, and next step for %s', (code) => {
    const help = describeStatusCode(code);
    expect(help.title.length).toBeGreaterThan(0);
    expect(help.description.length).toBeGreaterThan(0);
    expect(help.nextStep.length).toBeGreaterThan(0);
    expect(help.title).not.toBe('추가 확인이 필요합니다.');
  });

  it('does not guess a cause for an unknown status code', () => {
    expect(describeStatusCode('unknown_internal_code')).toEqual({
      title: '추가 확인이 필요합니다.',
      description: '현재 제공된 정보만으로 자세한 원인을 확인할 수 없습니다.',
      nextStep: '표시된 검사 상태를 기록하고 분석 담당자에게 확인하세요.',
    });
  });
});
