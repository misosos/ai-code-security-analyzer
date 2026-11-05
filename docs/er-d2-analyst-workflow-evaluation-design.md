# ER-D2 분석가 워크플로 비교 평가 설계

## 목적과 범위

이 평가는 기존 브라우저 Finding 비교와 ER-C2 증거 기반 평가가 **같은 두 ScanResponse**에서 제공하는 정보를 비교한다. 실험 단위는 출력 계약과 합성 시나리오이며, 사람의 정확도·속도·생산성·만족도를 측정하지 않는다. 결과를 제품 우월성이나 분석가 효과로 일반화하지 않는다.

기준 커밋은 `f409c23472a1ac0cb7c763108b60f11439003c43`, 시작 Gate는 GitHub Push CI `42019791673`이다. 기존 main의 작업 트리는 변경 상태였으므로 보존하고 새 worktree에서 평가한다.

## 비교 대상

### A — 기존 Finding Comparison

실제 구현은 `frontend/src/features/scans/compare.ts`의 `compareScanSnapshots()`다. 다음을 검사한다.

- 양쪽 Snapshot 존재, 정상 완료, 생략 Finding 0건
- ScanContext의 상태·대상·Rule Profile 일치
- Semgrep 버전 존재 및 일치
- 중복 Finding ID 및 응답 Count 일관성
- 같은 Snapshot 참조 여부

통과하면 정확한 Finding ID 집합 차이로 `currentOnly`, `shared`, `baselineOnly`를 만든다. `rescanFollowup.ts`와 UI는 범주별 분석가 후속 확인 안내를 제공하며, Finding ID만 비교하고 취약점 신규 발생·해결을 확정하지 않는다는 한계 문구를 표시한다. 이 보호 기능은 baseline에서 제외하지 않는다.

### B — Evidence-backed Investigation

같은 두 응답에 해당 실행의 Manifest가 Registry 안에서 결합된다. 비교 대상은 `/api/v2/investigations/evaluate`가 반환하는 `finding-disappearance-evaluation/v1`의 comparability, overall assessment, Finding 범주별 path observation/hypotheses 및 limitation codes다. 공개 응답에는 Manifest와 내부 Run Reference가 포함되지 않는다.

일반 Frontend comparator의 결과는 비교 projection으로 재사용한다. 전체 React 화면을 자동 구동한 평가가 아니므로 UI 사용성 결과로 해석하지 않는다.

## 사전 고정 연구 질문과 판정 기준

| 질문 | 확인 기준 | 기본 비교로 기대되는 정보 | 증거 조사로 추가되는 정보 | 허용하지 않는 결론 |
| --- | --- | --- | --- | --- |
| Q1 Finding 변화 | ID 집합 차이 세 범주 | 범주별 Finding | 같은 분류를 구조화 Evaluation에도 반환 | 의미적 Finding 동일성 |
| Q2 검사 경로 | 기준 전용 Finding 상대 경로와 현재 Scope | Finding 위치는 응답에 존재하나, 처리 경로 관찰은 없음 | 실제 Manifest가 보고한 경로 상태 | 모든 규칙의 적용·완료 |
| Q3 검사 제외 | Skip 관찰 여부 | 제공되지 않음 | 명시적 skip 또는 미수집/불가 상태를 구분할 수 있는 경우 코드화 | 자료 미수집을 제외 없음으로 해석 |
| Q4 소스 변경 | 두 검사 간 코드 변경 증거 | 제공되지 않음 | ER-C2도 일반 Source Snapshot을 수집하지 않음 | 코드 변경을 도구가 증명 |
| Q5 규칙 동일성 | Profile과 실제 바이트/로딩 집합 구분 | 요청 Profile 문맥만 보유 | 요청 Profile/선택된 파일 문맥, byte/loaded identity 제한 | 실제 적용 규칙 바이트 동일성 |
| Q6 해결 여부 | 명시적 해결 근거 여부 | 해결을 확정하지 않는 기존 제한 문구 | `UNDETERMINED`와 safety limitation | 취약점 해결·안전성 확정 |
| Q7 후속 조사 | 구체적 점검 방향 제시 | 범주별 Rescan Follow-up 작업 | 경로 관찰과 빠진 증거에 맞춘 추가 확인 방향 | 실제 후속 작업을 완료한 것으로 처리 |
| Q8 비교 차단 | 잘못된 입력에서 정상 비교 생성 여부 | 완료·중복·문맥·버전·Count Gate | Run Binding, target/profile 및 scan context Gate | 차단 오류를 빈 정상 결과로 표시 |

## 지표 및 코딩 규칙

점수나 가중 합계를 만들지 않는다. 각 시나리오/질문을 다음의 범주형 기록으로 코딩한다.

- **M1 Information Availability**: `AVAILABLE`, `PARTIALLY_AVAILABLE`, `UNAVAILABLE`, `NOT_APPLICABLE`. 질문 판정에 필요한 명시 정보가 모두 있으면 AVAILABLE, 일부만 있거나 간접적이면 PARTIALLY_AVAILABLE.
- **M2 Evidence Traceability**: `TRACEABLE`, `PARTIALLY_TRACEABLE`, `NOT_TRACEABLE`. 정보가 Response/Manifest/Evaluator 중 하나로 특정되고 같은 실행 연결이 확인되면 TRACEABLE. comparator의 계산 결과처럼 원본 값은 있으나 Manifest 연결이 없으면 PARTIALLY_TRACEABLE.
- **M3 Uncertainty Disclosure**: 중요한 질문 한계가 출력에 드러나면 `DISCLOSED`, 일부만이면 `PARTIAL`, 없으면 `NOT_DISCLOSED`, 해당 없으면 `NOT_APPLICABLE`.
- **M4 Unsupported Claim**: 고정된 금지 주장(수정 완료, 안전 확인, 악용 불가, 모든 규칙 완료)을 실제 출력이 했는지 `PRESENT`/`NONE`으로 검사한다. `NONE`은 시나리오에 한정한다.
- **M5 Follow-up Action Support**: 출력에서 직접 도출 가능한 후속 점검이 `SPECIFIC`, `PARTIAL`, `NONE`인지 기록한다. 실행 완료 여부와 분리한다.
- **M6 Invalid Comparison Handling**: `BLOCKED_WITH_REASON`, `BLOCKED_GENERIC`, `NORMAL_RESULT`, `NOT_TESTED`로 기록한다. HTTP Registry/API 차단과 기존 comparator 차단은 각각 해당 계층에서 관찰한 경우만 기록한다.

## 시나리오와 데이터 출처

1. **Finding disappearance (실제 Semgrep)**: ER-D1 합성 A/B → A/C. 기준·현재 응답은 동일 API 실행 결과이며, 두 방식에 같은 응답 객체의 값/ID를 입력한다. Fixture Truth인 파일 편집 사실은 결과 판정 입력으로 넣지 않는다.
2. **Evidence gap (같은 실제 실행의 증거)**: 시나리오 1의 기준 전용 Finding에서 Source Snapshot 및 실제 Rule Identity 부재를 평가한다. Skip 상태도 Registry의 실제 Manifest에서 별도 확인하되 공개 Evaluation Projection과 구별한다. 가짜 Manifest를 실측으로 표시하지 않는다.
3. **Invalid comparison (실제 API)**: 동일한 Run Handle을 양쪽으로 지정해 거부 결과를 관찰한다. Handle은 실행 출력과 문서에 보존하지 않는다.
4. **Zero / incomplete (계약 테스트)**: `tests/test_api_scan.py::test_partial_zero_findings_and_omission_are_explicit` 및 `tests/test_finding_disappearance_evaluator.py::test_no_finding_is_not_a_safety_statement_and_empty_difference_is_undetermined`, `test_incomplete_runs_remain_incomparable_even_with_positive_skip_observation`를 실행한다. 이 시나리오는 합성 adapter/dataclass 단위 fixture이며 실제 Semgrep 실행 사례와 합치지 않는다.

## 타당성 위협과 제한

- 시나리오가 합성 JavaScript와 baseline 규칙에 한정되어 실제 코드베이스 일반화는 지원하지 않는다.
- Comparator projection은 기존 TypeScript comparator의 Gate와 ID 집합 연산을 그대로 반영하되, React 렌더링이나 사람 상호작용을 재현하지 않는다.
- 두 방식의 공통 Finding 분류 결과가 같을 수 있다. 추가 정보의 존재가 판단의 정확도·시간·품질을 개선했다는 증거는 아니다.
- 실험자가 파일을 변경한 사실은 Fixture Truth다. Evaluator에는 제공하지 않는다.
- 단일 실행 수로 안정성/성능 통계를 만들지 않는다.
- 사용자가 실제 분석에 이 정보를 어떻게 활용하는지는 참가자 연구가 필요하다.

## 미지원 주장

이번 평가로 분석가 판단 정확도 향상, 업무 시간 단축, 오탐 감소, 생산성·만족도 향상, 취약점 해결 자동 판정, 도구의 전반적 우월성을 주장하지 않는다.
