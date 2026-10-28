# Analyst Review 이해도 채점표 — 진행자용

이 파일은 [참가자용 질문지](phase3c2-participant-questionnaire.md)와 분리해 보관하고 진행자만 사용한다. 실제 참가자가 답하지 않았다면 점수·평균·이해도 결과를 기록하거나 추정하지 않는다.

## 채점 방법

각 문항 0–2점, 총 22점이다.

- **2점:** 핵심 의미를 정확히 설명하고, 해당되는 오해를 명시적으로 배제함.
- **1점:** 핵심은 맞지만 중요한 제한/근거를 빠뜨리거나 설명이 모호함.
- **0점:** 허용되지 않는 결론을 내리거나 의미를 거꾸로 해석함.
- `N/A`: 참가자가 답변을 건너뛴 경우. 총점 분모에서 제외하고 제외 건수를 기록한다.

주관적 표현의 문장 유사도는 채점하지 않는다. 아래 기준에 따라 의미를 채점한다.

## 정답 및 오해 유형

| 문항 | 사전 채점 기준 | 0점 대표 오해 | 확인할 오해 유형 | 화면 근거 |
| --- | --- | --- | --- | --- |
| 1 | 1건은 Semgrep 검토 후보 수이며 취약점 확정 수가 아님 | “취약점이 하나 확정됐다” | Finding count = confirmed count | A의 검토 대상 문구 |
| 2 | `high`는 Semgrep의 severity 분류, 미검증은 확인 상태; 악용 가능성 미확정 | high라서 실제 악용 가능성이 확정 | Severity = verification/effectiveness | A의 severity·검증 상태 |
| 3 | 해당 신뢰 taint 규칙의 매치 보고; Source/Sink 선언은 있으나 실제 Source 위치와 전체 trace는 미확인 | 실제 외부 입력부터 sink까지 완전 확인 | Taint match = complete flow proof |
| 4 | 현재 근거에 Source 위치가 포함되지 않았다는 뜻; 위치/입력이 없다는 뜻은 아님 | Source가 존재하지 않음 | unavailable = absent in code |
| 5 | 구조화 trace가 결과에 제공되지 않음; 흐름 부재 또는 오탐을 뜻하지 않음 | 흐름이 없어 오탐 | trace absent = no flow/false positive |
| 6 | 일부 경로/규칙 누락 가능; 개별 보고 매치는 볼 수 있지만 전체 분석 완료나 미탐 부재를 말할 수 없음 | 정상 완료/전체 커버리지 보장 | partial = complete coverage |
| 7 | 안전하다고 결론 불가; 이번 설정·실행에서 보고된 Finding이 0건 | 코드 안전이 확인됨 | zero findings = safe |
| 8 | 사람이 직접 확인할 제안 작업; 완료 상태나 결론이 아님 | 체크리스트가 있으므로 검증 완료 | suggested task = completed control |
| 9 | Consumer/Gate의 입력·claim 구조 연결 검증; 의미적 보안 주장이나 취약점이 맞다는 검증 아님 | 근거 검증 통과 = 취약점 확정 | structural validation = semantic truth |
| 10 | 실패 카드는 확인 사실을 제공하지 않음; 이를 사실로 인용하지 않고 스캔/근거 문제 해결 또는 원자료 직접 검토 | 실패한 카드도 정상 확인 결과로 사용 | validation failure = trusted evidence |
| 11 | 일반 pattern은 규칙 패턴 매치 보고다. 이 자료에서 Source→Sink/taint 주장은 지원되지 않으며 화면 A의 taint 유형과 구분해야 함 | pattern 매치 자체가 taint 흐름을 확인 | Pattern match = taint flow | D의 탐지 유형, 확인·제한 claim |


## 평가 결과 기록 양식

참가자별로 익명 코드, 경험 범주(선택), 11개 문항의 점수/N/A만 최소 기록한다. 이름·이메일·회사/팀명·실제 코드·실제 보안 사건 정보는 수집하지 않는다.

향후 분석 시 다음을 구분한다.

- 참석자 수와 경험 범주별 수
- 유효 답변 문항 수 및 N/A 수
- 문항별 정답률과 오답 유형
- 총점 분포 (평균만 단독 보고하지 않음)
- 진행자 설명이 필요했던 문항
- 소표본 한계 및 참가자 모집 편향

표본이 작으면 일반 사용자 집단의 이해도를 대표한다고 해석하지 않는다. 설문 만족도나 응답 시간을 측정하지 않았다면 보고하지 않는다.
