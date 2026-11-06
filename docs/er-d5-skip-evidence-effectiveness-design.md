# ER-D5 — Skip Evidence 실효성 평가 설계

## 목적과 범위

ER-D4 조사 모드의 Skip Evidence가 기존 일반 검사 비교에 비해 추가로 제공하는 사실을 실제 Semgrep/API/브라우저 경로에서 확인한다. 평가는 출력 정보와 실행 계약을 대상으로 한다. 분석가의 정확도, 조사 시간, 오판률, 만족도는 측정하지 않는다.

제품 공개 계약을 변경하지 않는다. 기본 v1 실행, Finding ID, ScanResponse, C1 Manifest v1, C2 Evaluation v1, Registry 및 UI의 보수적 상태 의미를 유지한다.

## 고정 질문과 판정 기준

| 질문 | 검증 기준 | 허용되는 결론 | 허용하지 않는 결론 |
| --- | --- | --- | --- |
| Q1 Skip 증거 추가 | 같은 합성 파일 상태에서 v1 응답과 별도 v2 Run의 Registry/Evaluation을 비교 | v2가 allowlisted path/reason을 Run에 연결해 반환하는지 | v1과 v2가 같은 Invocation인 것처럼 Session 구성 |
| Q2 추가 증거의 의미 | Finding B의 경로 관찰·가설·aggregate 상태 확인 | Semgrep이 해당 경로를 `.semgrepignore` 사유로 제외했다고 보고했다는 절차 관찰 | 취약점 해결 또는 소멸의 유일 원인 확정 |
| Q3 잔여 불확실성 | limitation code와 Manifest completeness 확인 | 코드 변경, loaded rules, 전체 Scope, 악용 가능성은 계속 미확정 | 미관찰을 안전성 증명으로 취급 |
| Q4 UI 전달 | 실제 Chromium에서 실제 FastAPI/Semgrep 흐름과 UI 문구 검사 | Partial, comparator 차단, Skip 관찰, 전체 INCOMPARABLE이 표시되는지 | 텍스트 자동 검증을 사용자 이해도 수용으로 표현 |

## 공정한 비교 조건

실험군 A는 `/api/v1/scans`의 기존 비-verbose 실행 두 번이다. 실험군 B는 같은 합성 파일 상태를 별도로 재현한 두 `/api/v2/investigation-scans` verbose Run이다. v1과 v2 Invocation ID는 다르므로 서로 다른 군의 Run을 하나의 Session에 넣지 않는다. 각 군 안에서만 baseline/current 비교가 이뤄진다.

양 군 모두 같은 trusted local baseline rules와 `stable.js` / `retired.js`의 합성 내용 및 ignore 상태를 사용한다. 독립 실행이므로 이를 동일 Semgrep 실행 또는 byte-identical process input이라고 부르지 않는다. Finding ID partition이 일치하는지 출력으로 검증한다.

## 지표

ER-D2 M1~M6 범주를 유지하되 임의 점수나 향상률은 계산하지 않는다.

- **M1 Information Availability:** 정보 존재 수준 `AVAILABLE` / `PARTIALLY_AVAILABLE` / `UNAVAILABLE` / `NOT_APPLICABLE`.
- **M2 Evidence Traceability:** 실제 응답·Manifest·Evaluator 연결 수준 `TRACEABLE` / `PARTIALLY_TRACEABLE` / `NOT_TRACEABLE`.
- **M3 Uncertainty Disclosure:** 한계 노출 `DISCLOSED` / `PARTIAL` / `NOT_DISCLOSED`.
- **M4 Unsupported Claim:** 평가 대상 출력에서 근거 없는 해결·안전·완전성 주장의 존재 여부.
- **M5 Follow-up Action Support:** 실제 후속 행동의 완료가 아니라, 무엇을 더 확인할지 정보가 제공되는 수준.
- **M6 Invalid Comparison Handling:** 잘못된 Run/Session 연결의 거부와 정상 평가의 구분.

UI의 문자열 존재와 실제 사용자가 이해했다는 판단은 구분한다.

## 시나리오

1. **기본 v1:** Finding A/B 기준과 `.semgrepignore`로 B를 제외한 재검사. Finding partition, public ScanStatus, Scope/Skip 필드 노출 여부를 관찰한다.
2. **조사 v2:** 같은 synthetic states를 재구성해 verbose baseline/current를 등록한다. 현재 Run의 Partial 상태, Registry의 path/reason, Evaluation의 Finding별 Skip 관찰과 aggregate 상태를 검증한다.
3. **실제 브라우저:** 격리된 FastAPI–Semgrep–Chromium E2E에서 UI의 Partial 안내, 기존 Comparator 차단, 조사 결과, `INCOMPARABLE`, Release 후 재사용 차단을 검사한다.
4. **부정/경계 사례:** 기존 계약 테스트에서 unknown reason, traversal, 경로 충돌, 구조·count 제한, 정상 0건/부분 검사, Target/Profile/Invocation mismatch, 동일 Run, 만료·Release, Finding partition/context mismatch를 확인한다. 해당 입력이 synthetic contract test이면 실제 Semgrep 실험이라고 표현하지 않는다.

## 타당성 위협

- 합성 JavaScript, 저장소 baseline rules, Semgrep 1.182.1에 한정된다.
- v1과 v2는 별도 실행이다. 같은 파일 조건은 같은 실행을 뜻하지 않는다.
- API의 내부 Registry 자료는 UI에 원문으로 노출되지 않는다. 화면에서 관찰한 것은 public Evaluation Projection뿐이다.
- Playwright Chromium은 실제 macOS Safari 수동 사용성이나 사용자 이해도를 증명하지 않는다.
- 단일 실행 조합으로 시간·성능·오류율 일반화는 하지 않는다.

## 미지원 주장

분석가 정확도/속도 향상, 사용자 만족도, 취약점 해결, 코드 변경 인과, 실제 로딩 규칙 동일성, 모든 Scope 완료, 악용 가능성, 다중 사용자 운영을 주장하지 않는다.
