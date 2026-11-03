import { describe, expect, it } from 'vitest';
import type { ApiFinding, ScanResponse } from '../src/api/types';
import { createScanTriage } from '../src/features/scans/findingTriage';

const finding = (overrides: Partial<ApiFinding> = {}): ApiFinding => ({
  finding_id: 'semgrep:0123456789abcdef01234567',
  rule_id: 'baseline.javascript-dynamic-eval',
  severity: 'high',
  verification_status: 'unverified',
  finding_kind: 'pattern',
  file_path: 'src/review.js',
  line_number: 12,
  evidence_validation_status: 'validated',
  supported_claims: ['match_reported'],
  restricted_claims: [],
  validation_error_code: null,
  ...overrides,
});

const scan = (findings: ApiFinding[] = [finding()], overrides: Partial<ScanResponse> = {}): ScanResponse => ({
  scan_status: 'completed',
  completed: true,
  semgrep_version: '1.182.1',
  finding_count: findings.length,
  displayed_finding_count: findings.length,
  omitted_finding_count: 0,
  severity_counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
  issues: [],
  findings,
  limitations: [],
  ...overrides,
});

describe('Finding triage guidance', () => {
  it('validated high는 위험 점수가 아닌 우선 코드 검토 제안을 제공한다', () => {
    const result = createScanTriage(scan()).findings[0];
    expect(result.recommendation).toBe('priority_code_review');
    expect(result.explanation).toContain('실제 취약점 여부와 악용 가능성은 추가 확인이 필요합니다');
    expect(result.basis).toEqual(expect.arrayContaining(['Semgrep 도구 심각도: 높음 (high)', '근거 연결 검증: validated']));
    expect(result).not.toHaveProperty('score');
    expect(result.supportedClaims).toEqual(['match_reported']);
  });

  it('validated critical도 같은 우선 검토 제안을 사용하고 숫자 위험 점수를 만들지 않는다', () => {
    const result = createScanTriage(scan([finding({ severity: 'critical' })])).findings[0];
    expect(result.recommendation).toBe('priority_code_review');
    expect(result.recommendationLabel).toBe('우선 코드 검토 권장');
    expect(Object.keys(result).some((key) => /score|cvss/i.test(key))).toBe(false);
  });

  it.each(['medium', 'low', 'info'] as const)('validated %s는 코드 검토를 권장한다', (severity) => {
    const result = createScanTriage(scan([finding({ severity })])).findings[0];
    expect(result.recommendation).toBe('code_review');
  });

  it.each(['rejected', 'unavailable'] as const)('%s high는 원래 심각도를 보존하고 근거 연결 확인을 먼저 권한다', (status) => {
    const result = createScanTriage(scan([finding({ evidence_validation_status: status })])).findings[0];
    expect(result.recommendation).toBe('evidence_review');
    expect(result.severity).toBe('high');
    expect(result.explanation).toContain('근거 연결 확인이 먼저 필요합니다');
  });

  it('medium validated unclassified finding은 유형을 추정하지 않고 일반 검토 절차를 제공한다', () => {
    const result = createScanTriage(scan([finding({ finding_kind: 'unclassified', rule_id: 'unknown.rule', severity: 'medium' })])).findings[0];
    expect(result.recommendation).toBe('code_review');
    expect(result.ruleTitle).toBe('분류되지 않은 Finding 검토');
    expect(result.tasks.join(' ')).toContain('분류에 필요한');
  });

  it('Taint 및 일반 Pattern 안내를 유형별로 구분한다', () => {
    const taint = createScanTriage(scan([finding({ finding_kind: 'taint', rule_id: 'experimental.unknown' })])).findings[0];
    const pattern = createScanTriage(scan([finding({ rule_id: 'unknown.rule' })])).findings[0];
    expect(taint.tasks.join(' ')).toContain('Source/Sink');
    expect(pattern.tasks.join(' ')).toContain('규칙과 일치한 코드');
    expect(taint.explanation).not.toContain('실제 Source–Sink 경로가 확인됐습니다');
  });

  it('baseline 세 규칙에 고정된 단계 및 권장 조치를 제공한다', () => {
    const cases = [
      ['baseline.javascript-dynamic-eval', 'eval', 'JSON'],
      ['baseline.react-dangerous-html', 'dangerouslySetInnerHTML', '일반 텍스트'],
      ['baseline.firestore-unconditional-write', 'match', '최소 권한'],
    ] as const;
    for (const [rule_id, taskNeedle, actionNeedle] of cases) {
      const result = createScanTriage(scan([finding({ rule_id })])).findings[0];
      expect(result.tasks.join(' ')).toContain(taskNeedle);
      expect(result.actions.join(' ')).toContain(actionNeedle);
    }
  });

  it('partial, failed, timeout 및 omitted 결과에 범위 경고를 붙인다', () => {
    for (const scan_status of ['partial', 'execution_failed', 'timed_out'] as const) {
      const result = createScanTriage(scan([finding()], { scan_status, completed: false })).findings[0];
      expect(result.scopeNotice).toContain('현재 응답에 표시된 Finding만');
    }
    const omitted = createScanTriage(scan([finding()], { finding_count: 2, omitted_finding_count: 1 })).findings[0];
    expect(omitted.scopeNotice).toContain('1개 Finding이 생략');
  });

  it('Finding 0건은 빈 결과로 두고 검사 완료/생략 범위를 요약한다', () => {
    expect(createScanTriage(scan([])).findings).toEqual([]);
    expect(createScanTriage(scan([], { scan_status: 'partial', completed: false })).scopeNotice).toContain('부분 검사');
  });

  it('같은 규칙 Finding은 각각 생성하고 입력 순서를 바꾸지 않는다', () => {
    const first = finding({ finding_id: 'semgrep:aaaaaaaaaaaaaaaaaaaaaaaa', file_path: 'a.js' });
    const second = finding({ finding_id: 'semgrep:bbbbbbbbbbbbbbbbbbbbbbbb', file_path: 'b.js' });
    const result = createScanTriage(scan([second, first])).findings;
    expect(result.map((item) => item.findingId)).toEqual([second.finding_id, first.finding_id]);
    expect(result.map((item) => item.filePath)).toEqual(['b.js', 'a.js']);
  });

  it('검토 완료 상태와 원본 Finding은 triage 계산으로 변하지 않는다', () => {
    const original = finding();
    const before = structuredClone(original);
    const result = createScanTriage(scan([original])).findings[0];
    const analystStatus = 'reviewed';
    expect(analystStatus).toBe('reviewed');
    expect(result.recommendation).toBe('priority_code_review');
    expect(original).toEqual(before);
    expect(result).not.toHaveProperty('analystReviewStatus');
  });

  it('사용자 제어 식별자를 화면 문구로 해석하거나 HTML 문자열로 반환하지 않는다', () => {
    const result = createScanTriage(scan([finding({ rule_id: '<img src=x onerror=alert(1)>' })])).findings[0];
    expect(result.ruleTitle).toBe('규칙 매치 검토');
    expect(result.ruleId).toBe('<img src=x onerror=alert(1)>');
    expect(`${result.ruleTitle} ${result.ruleFinding} ${result.explanation} ${result.tasks.join(' ')}`).not.toContain('<img');
  });
});
