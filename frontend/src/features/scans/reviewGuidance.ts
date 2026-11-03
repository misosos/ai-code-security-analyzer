import type { FindingKind } from '../../api/types';

export interface RuleReviewGuidance {
  title: string;
  finding: string;
  tasks: readonly string[];
  actions: readonly string[];
}

export interface FindingReviewGuidance {
  title: string;
  finding: string;
  tasks: readonly string[];
  actions: readonly string[];
}

const ruleGuidance: Readonly<Record<string, RuleReviewGuidance>> = {
  'baseline.javascript-dynamic-eval': {
    title: 'JavaScript 동적 코드 실행',
    finding: 'Semgrep이 JavaScript 동적 코드 실행 패턴과 일치하는 코드를 보고했습니다.',
    tasks: [
      '`eval` 또는 `new Function` 사용 위치와 전달 인자를 확인합니다.',
      '호출 인자가 어디에서 생성되고 어떤 함수·변수를 거쳐 전달되는지 검토합니다.',
      '외부 입력이 인자 값을 제어할 수 있는지 확인합니다.',
      '호출에 도달하는 실행 조건과 관련 권한을 검토합니다.',
      '동적 코드 실행을 제거하거나 JSON 파싱 등 목적에 맞는 방식으로 바꿀 수 있는지 검토합니다.',
      '허용된 동작만 처리하는 명시적 분기 구조를 대안으로 검토합니다.',
    ],
    actions: [
      '불필요한 `eval` 또는 `new Function` 사용 제거를 검토합니다.',
      '데이터 처리는 JSON 파싱 등 목적에 맞는 비실행 방식으로 대체할 수 있는지 검토합니다.',
      '필요한 동작만 허용하는 명시적 분기 구조를 검토합니다.',
    ],
  },
  'baseline.react-dangerous-html': {
    title: 'React의 HTML 삽입 패턴',
    finding: 'Semgrep이 JSX의 `dangerouslySetInnerHTML` 사용 패턴을 보고했습니다.',
    tasks: [
      '`dangerouslySetInnerHTML` 사용 위치와 `__html`에 전달되는 값을 확인합니다.',
      '해당 값의 생성 지점과 신뢰 경계, 외부 입력의 영향 여부를 검토합니다.',
      'HTML 정제 처리가 있다면 출력 문맥에 적합한지와 적용 위치를 확인합니다. 정제 효과는 이 안내에서 확인되지 않았습니다.',
      '실제 렌더링 경로와 적용되는 방어 조건을 검토합니다.',
      'HTML 삽입이 필요하지 않다면 일반 텍스트 출력으로 대체 가능한지 검토합니다.',
    ],
    actions: [
      '불필요한 HTML 직접 삽입 제거를 검토합니다.',
      'HTML 삽입이 필요하면 출력 문맥에 적합한 검증·정제 방식을 검토합니다. 이 안내는 Sanitizer의 존재나 효과를 확인하지 않았습니다.',
      '일반 텍스트 출력으로 대체 가능한지 검토합니다.',
    ],
  },
  'baseline.firestore-unconditional-write': {
    title: 'Firestore 쓰기 권한 조건',
    finding: 'Semgrep이 Firestore 규칙에서 조건이 리터럴 `true`인 쓰기 권한 패턴을 보고했습니다.',
    tasks: [
      '표시된 `firestore.rules` 위치의 `allow` 선언과 해당 `match` 경로를 확인합니다.',
      '상위·중첩 `match` 범위와 겹치는 권한 선언을 함께 검토합니다.',
      '인증, 사용자 소유권, 데이터 조건이 실제 정책에서 어떻게 적용되는지 확인합니다.',
      '배포된 규칙이 로컬 파일과 같은지 별도로 확인합니다. 이 안내는 배포 상태를 조회하지 않았습니다.',
      '쓰기 권한이 필요한 리소스와 작업 범위를 확인합니다.',
    ],
    actions: [
      '무조건 쓰기 허용의 필요성과 적용 범위를 재검토합니다.',
      '인증 및 리소스 소유권 조건을 적용할 수 있는지 검토합니다.',
      '필요한 최소 권한만 허용하도록 경로와 작업 범위를 좁히는 방안을 검토합니다.',
    ],
  },
};

const genericGuidance: Readonly<Record<FindingKind, FindingReviewGuidance>> = {
  pattern: {
    title: '규칙 매치 검토',
    finding: 'Semgrep이 규칙과 일치하는 패턴을 보고했습니다. 실제 입력 영향과 실행 조건은 별도로 확인해야 합니다.',
    tasks: [
      '표시된 위치에서 규칙과 일치한 코드와 주변 조건을 확인합니다.',
      '관련 값의 출처와 실행 지점까지의 전달 경로를 검토합니다.',
      '입력 검증·권한 확인·정제 등 방어 조건과 적용 범위를 확인합니다.',
      '해당 코드 경로의 실행 조건과 권한을 검토합니다.',
    ],
    actions: [
      '탐지된 패턴이 필요한지와 더 제한적인 구현이 가능한지 검토합니다.',
      '확인된 입력 경로와 방어 조건에 맞는 최소 변경을 검토합니다.',
    ],
  },
  taint: {
    title: 'Taint 흐름 검토 후보',
    finding: 'Semgrep 응답이 이 Finding을 Taint 유형으로 분류했습니다. 이는 도구 응답의 분류이며 실제 입력 도달 경로나 취약점 확정을 뜻하지 않습니다.',
    tasks: [
      '응답에서 구조적으로 확인된 Source/Sink 규칙 선언과 실제 코드 위치를 구분해 확인합니다.',
      'Source와 Sink 위치 및 두 지점 사이의 전달 경로를 코드에서 직접 검토합니다.',
      '응답에 제공된 Flow Trace와 Sanitizer 근거의 범위를 확인하고, 자료가 없으면 직접 검증합니다.',
      '입력 검증, 정제 효과와 실행 도달 조건을 별도로 확인합니다.',
    ],
    actions: [
      '실제 입력 경로와 Sink 도달 여부를 확인한 뒤 필요한 방어 조치를 검토합니다.',
      '정제 또는 검증을 고려할 때는 적용 문맥과 효과를 별도로 확인합니다.',
    ],
  },
  unclassified: {
    title: '분류되지 않은 Finding 검토',
    finding: '응답에서 탐지 유형을 확정할 수 없습니다. 규칙과 근거 연결을 확인해야 합니다.',
    tasks: [
      '규칙 ID, 매치 위치와 근거 연결 상태를 확인합니다.',
      '분류에 필요한 Source/Sink 또는 패턴 문맥이 결과에 있는지 확인합니다.',
      '주변 입력 출처, 방어 조건과 실행 경로를 직접 검토합니다.',
    ],
    actions: [
      '분류와 근거가 확인되기 전에는 특정 취약점 유형이나 수정 방식을 가정하지 않습니다.',
      '확인된 코드 맥락과 프로젝트 정책에 따라 후속 조치를 결정합니다.',
    ],
  },
};

export function getFindingReviewGuidance(ruleId: string, findingKind: FindingKind): FindingReviewGuidance {
  const known = Object.hasOwn(ruleGuidance, ruleId) ? ruleGuidance[ruleId] : undefined;
  return known ?? genericGuidance[findingKind];
}

export function hasKnownRuleGuidance(ruleId: string): boolean {
  return Object.hasOwn(ruleGuidance, ruleId);
}
