# ER-D2 분석가 워크플로 비교 평가 결과

## 요약

실제 Semgrep 1.182.1로 합성 JavaScript 두 번을 검사했다. **두 방법은 Finding ID 집합 차이(A 유지, B 기준 전용, C 현재 전용)를 똑같이 분류했다.** 증거 기반 평가에 추가된 정보는 기준 전용 경로의 처리 관찰, 실행 증거 연결을 거친 제한된 가설 상태, Rule/Source/Scope 한계 코드였다. 이 추가 정보에도 B의 원인은 `UNDETERMINED`였다.

실제 참가자 연구는 수행하지 않았다. 결과는 출력 계약의 정보 차이를 평가하며, 판단 정확도·업무 시간·생산성 향상을 뜻하지 않는다.

## 환경 및 평가 입력

- 기준 SHA: `f409c23472a1ac0cb7c763108b60f11439003c43`
- GitHub 기준 Push CI: `42019791673` — 세 필수 Job success, Artifacts 0
- Python 3.12.7, uv 0.11.26, Semgrep 1.182.1, Node.js 24.22.2
- 합성 파일: `stable.js`, `retired.js`, `added.js`; 신뢰된 저장소 baseline rules
- 두 방법은 실제 v2 API가 반환한 **동일한 두 ScanResponse 객체의 값**을 사용했다. 브라우저 comparator는 기존 TypeScript 로직과 같은 gate 및 Finding ID 집합 연산을 적용한 `comparison projection`이다. 전체 React 화면에서 평가를 수행한 것은 아니다.
- 실험자가 `retired.js`를 바꾼 사실은 Fixture Truth다. 이를 Analyzer 입력·근거로 주입하지 않았다.

## 시나리오 결과

### Scenario 01 — Finding 소멸 (실제 Semgrep 및 API)

| Finding | 기준 응답 | 현재 응답 | 기존 비교 projection | 서버 Evaluation |
| --- | --- | --- | --- | --- |
| A `stable.js` | 관찰 | 관찰 | `shared` | `shared` |
| B `retired.js` | 관찰 | 미관찰 | `baselineOnly` | `baselineOnly`, `PATH_REPORTED_SCANNED`, Skip 가설 `CONTRADICTED` |
| C `added.js` | 미관찰 | 관찰 | `currentOnly` | `currentOnly` |

서버 결과는 `COMPARABLE`, 전체 평가는 `UNDETERMINED`였다. Source Snapshot 가설과 Rule Identity 가설도 `UNDETERMINED`였다. 현재 Manifest는 `retired.js`를 처리 경로로 보고했지만, 이 사실은 모든 규칙의 적용이나 분석 완료를 입증하지 않는다. 전체 제한에는 `source_snapshot_not_collected`, `rule_bytes_unverified`, `loaded_rule_identity_unverified`, `scope_completeness_unverified`, `scan_result_is_not_safety_proof`가 포함됐다.

### Scenario 02 — Evidence Gap (동일 실제 실행의 내부 Manifest 및 공개 Evaluation)

현재 Run Manifest의 `skipped_status`는 `NOT_COLLECTED`였다. 이 내부 확인값은 결과 Projection에 상태 하나만 남겼으며 Manifest 원문은 저장하지 않았다. B의 경로가 `scanned`로 보고되어 공개 Evaluation은 `PATH_REPORTED_SCANNED`와 Skip 가설 `CONTRADICTED`를 반환했다. 따라서 이 Finding에 대해 API 응답은 “Skip 목록 미수집”을 별도 Finding 상태로 노출하지 않는다. Q3의 공개 정보 가용성은 **부분적**이다.

Source Snapshot, 규칙 바이트 동일성, 실제 로딩된 Rule Identity, 전체 Scope 완전성은 각각 미수집 또는 미검증으로 제한 코드에 나타났다. 코드 변경 사실이나 원인은 확인되지 않았다.

### Scenario 03 — Invalid Comparison (실제 API 요청)

같은 Run Handle을 기준과 현재에 지정했을 때 API는 HTTP `409 binding_rejected`를 반환했다. 정상 Evaluation이나 빈 Finding 결과는 생성되지 않았다. Session Release 후 같은 Session을 평가하면 HTTP `404 evidence_unavailable`였다. 원문 Handle은 결과 문서에 남기지 않았다.

기존 UI comparator는 같은 `ScanSnapshot` 객체 참조를 `same_scan_snapshot`으로 차단한다. 이는 메모리 객체 동일성 검사이며 영속적인 Scan Reference 검증은 아니다. 두 개의 다른 객체가 같은 실행에서 왔는지 기존 v1 비교가 증명할 수는 없다.

### Scenario 04 — Zero Finding / Incomplete (계약 테스트)

합성 adapter/Bundle 단위 테스트에서 정상 0 Finding은 빈 집합 비교이지만 안전성 주장은 아니며 Evaluator 전체 상태는 `UNDETERMINED`였다. 부분·실패 검사와 Finding 생략은 정상 완료 비교로 승격되지 않았다. 이것은 실제 Semgrep zero-Finding 실험이 아니라 테스트 fixture 결과다.

실행 테스트: `test_partial_zero_findings_and_omission_are_explicit`, `test_no_finding_is_not_a_safety_statement_and_empty_difference_is_undetermined`, `test_incomplete_runs_remain_incomparable_even_with_positive_skip_observation` — 7 passed.

## 질문별 결과

표에서 “기본”은 실제 `compareScanSnapshots()`와 기존 follow-up 문구를 포함한다. “조사”는 같은 ScanResponse와 실제 API Evaluation이다.

| 질문 | 기본 비교 | 증거 기반 조사 | 추가 정보 | 남은 한계 |
| --- | --- | --- | --- | --- |
| Q1 Finding 변화 | `shared=1`, `baselineOnly=1`, `currentOnly=1` | 동일한 세 범주와 각 1건 | 차이 없음 | ID 범주는 의미상 동일성을 보증하지 않음 |
| Q2 검사 경로 | Finding의 상대 경로는 응답에 있음. 처리 Scope 주장은 없음 | B에 `PATH_REPORTED_SCANNED` | Semgrep 경로 처리 보고 추가 | 모든 규칙 적용·완료는 미증명 |
| Q3 검사 제외 | 제외 관찰 정보 없음 | B는 Skip 가설 `CONTRADICTED`; 실제 Manifest의 Skip 목록은 `NOT_COLLECTED` | 해당 경로가 처리 대상으로 보고됐다는 제한된 관찰 | 공개 응답은 Skip 수집 상태를 별도 상태로 보여주지 않음 |
| Q4 소스 변경 | 코드 변경 증거 없음 | `source_snapshot_not_collected`; 가설 `UNDETERMINED` | 부재한 Source Snapshot을 명시 | 변경 여부와 원인 판단 불가 |
| Q5 규칙 동일성 | Profile 문맥 비교 가능 | Profile/선택 규칙 문맥 및 `rule_bytes_unverified`, `loaded_rule_identity_unverified` | 실제 규칙 identity의 미검증을 명시 | 실제 적용·로딩 바이트 동일성 미증명 |
| Q6 해결 여부 | 기존 UI 제한 문구가 해결 확정을 금지 | `UNDETERMINED`, `scan_result_is_not_safety_proof` | 판단 보류와 한계 코드가 구조화됨 | 양쪽 모두 해결 판정 불가 |
| Q7 후속 조사 | 범주별 구체적인 점검 작업 제공 | Scope 관찰과 제한을 추가로 참고 가능 | 어떤 근거가 비어 있는지 좁힐 수 있음 | Evaluator는 Git Diff/규칙/실행경로를 확인하지 않음. 기존 checklist가 더 구체적인 항목도 있음 |
| Q8 비교 차단 | 상태·생략·중복·문맥·버전·Count 불일치 차단 | 동일 Run은 409, 해제 Session은 404 | 서버가 실행 provenance와 수명을 검사 | 기존 comparator는 내구성 있는 실행 ID를 갖지 않음 |

## 지표 결과

사전 기준은 [평가 설계](er-d2-analyst-workflow-evaluation-design.md)에 고정했다. 점수 합계는 계산하지 않았다.

| 지표 | 기본 비교 | 증거 기반 조사 | 관찰 |
| --- | --- | --- | --- |
| M1 Information Availability | Finding 분류 AVAILABLE; Q2~Q5의 증거 상태 UNAVAILABLE/PARTIAL | Finding 분류 AVAILABLE; Q2 AVAILABLE, Q3 PARTIALLY_AVAILABLE, Q4/Q5에서 증거 부재 상태 PARTIALLY_AVAILABLE | 추가 정보는 제한된 범위·identity 상태에 집중 |
| M2 Evidence Traceability | Finding Response와 ID 집합 연산에 PARTIALLY_TRACEABLE | Registry 내부에서 Response/Manifest binding 후 Evaluation. 외부 출력은 내부 Manifest/Reference를 감추므로 PARTIALLY_TRACEABLE | 내부 결합은 강화되지만 사용자가 원본 Manifest를 직접 감사할 수는 없음 |
| M3 Uncertainty Disclosure | 해결 불가 및 ID 제한은 표시; Source/Rule/Scope 세부는 부분 공개 | Source Snapshot·Rule identity·Scope 완전성의 제한 코드를 표시; Skip 목록 상태는 이번 경로에서 별도 미표시 | 모든 수집 공백이 동일한 수준으로 노출되지는 않음 |
| M4 Unsupported Claim | 이번 출력의 금지 주장 0건 | 이번 출력의 금지 주장 0건 | 기존 비교도 이미 보수적 안전 문구를 보유 |
| M5 Follow-up Action Support | 범주별 명시적 작업 목록: SPECIFIC | 평가 코드는 추가 증거 위치를 좁히지만 자체 후속 작업 목록은 아님: PARTIAL | 근거 관찰과 조치 checklist는 상호 보완적 |
| M6 Invalid Comparison Handling | 기존 객체/문맥 gate 및 불완전 상태 거부 | 동일 Run 409, Release 후 404; 정상 결과와 구분 | 조사 API는 실제 Run/Session 수명까지 검증 |

M4는 합성 시나리오의 comparator 문구·API 결과에서만 검사했다. 전체 코드베이스 모든 화면·외부 사용 경로에 대한 일반 보증이 아니다. M5는 실제 수행 작업의 완료를 의미하지 않는다.

## 분석가 판단 기록

**관찰 사실:** 두 정상 완료 ScanResponse 사이에서 B의 Finding ID는 현재 응답에 없었다. Semgrep은 현재 실행에서 B의 파일 경로를 처리 경로로 보고했다.

**현재 판단:** 관찰 집합은 비교 가능하지만 B가 사라진 원인은 `UNDETERMINED`다. Skip 원인은 이번 좁은 Scope 관찰에서 뒷받침되지 않았다.

**확인되지 않은 내용:** 코드 Snapshot/변경, 실제 규칙 바이트와 로딩 집합, 전체 Scope 완료, 실제 취약점 영향.

**추가 확인:** 분석가는 별도 Git Diff, 현재 코드와 실행경로, 선택 및 로딩 규칙, ignore 설정을 확인하고 동일 조건 재검사나 수동 영향 검증을 수행할 수 있다.

**종결 조건:** 특정 원인을 지지/배제하려면 해당 원인에 직접 연결되는 코드 이력, 규칙·설정 또는 실행 기록이 추가로 필요하다. 제품이 자동 해결 판정을 하지 않는다.

## 해석과 제한

### 확인된 추가 정보

같은 입력 Finding 분류를 유지하면서 조사 경로 처리 보고와 명시적인 Source/Rule/Scope 근거 부족 코드를 추가로 얻었다. 같은 Run을 재사용하거나 해제된 Session을 다시 평가하는 시도는 정상 결과 대신 차단됐다.

### 해결하지 못한 문제

Finding 미관찰의 실제 원인, 코드 변경, 완전한 규칙 동일성, 취약점 해결 여부는 확인되지 않았다. Skip 자료가 수집되지 않은 상태는 B의 경로 처리 관찰과 별개로 남았다.

### 사람 대상 검증이 필요한 효과

추가 정보가 실제 분석가의 판단 정확도, 조사 시간, 오판률 또는 만족도를 개선하는지는 참가자 비교 실험이 필요하다. ER-D2에서는 측정하지 않았다.

`Finding의 미관찰은 취약점 수정이나 해결 완료의 증거가 아니다.`
