# ER-D5 — 다음 Evidence 개발 결정

## 결정

다음 연구 후보: **A — 선택된 신뢰 규칙 파일 바이트 일치 관찰**

상태: `ER_D6_IMPLEMENTATION_CANDIDATE_SELECTED`

이는 ER-D6 구현 승인이나 공개 계약 변경 승인이 아니다. ER-D5의 격리 실험 결과와 D3의 feasibility 기록을 토대로 후속 설계에서 검토할 1순위 후보를 정한 것이다.

## ER-D4에서 확인된 가치

실제 Semgrep 1.182.1 조사 실행은 Finding B의 경로를 `semgrepignore_patterns_match` 사유로 제외했다고 보고했다. 이에 따라 분석가는 해당 Ignore 설정과 경로를 우선 조사할 수 있다. 이 정보는 Finding partition 자체를 바꾸지 않고, partial Scan과 aggregate `INCOMPARABLE`을 유지한다.

## 남은 공백 후보 비교

| 후보 | 추가 가능한 관찰 | 여전히 미검증 | 보호/회귀 위험 | 비용 및 권고 |
| --- | --- | --- | --- | --- |
| A. Selected Rule Bytes Identity | 실행 시 선택된 신뢰 파일의 digest/equality 상태를 비교해 profile 아래 선택 파일 내용이 달랐는지 관찰 | Semgrep이 실제 로딩한 전체 규칙 inventory, parser/plugin/환경, 파일을 읽은 정확한 순간, 규칙 변화와 Finding 소멸의 인과 | Digest 자체도 상관 식별 정보를 노출할 수 있음; 재열기 TOCTOU; C1 strict serialization/schema 및 제한 코드 의미 | digest를 외부에 공개하지 않는 equality projection을 검토하면 소스 원문 유출보다 위험이 낮고, 규칙 차이라는 한 가지 confounder를 줄일 수 있음. 중간 구현 비용 |
| B. Source Change Evidence | 검사 전후에 제한된 파일 내용/크기/digest가 달라졌는지 관찰 | Semgrep 실제 입력 바이트 연결, scan 중 파일 경쟁, 변경과 특정 Finding 소멸 사이의 인과, 파일 추가/이동/생성 범위 | 소스 기반 digest는 민감한 상관 정보가 될 수 있고 소스 경로·파일 집합을 추가 보존할 위험이 큼 | 프라이버시·race·Scope 설계 비용이 큼. 현재 우선순위 아님 |
| C. Scope Evidence 보완 | 이미 관찰한 ignore 외 Semgrep `errors`, `skipped_rules`, 향후 지원 skip reason의 세부 구분 | 모든 경로/규칙 조합의 적용 성공, 완전한 Scope, Semgrep 버전별 출력 의미 | 임의 reason allowlist 확장은 오판 및 민감 문자열 저장 위험; 현재 C1은 error/skipped_rules count만 수집 | 추가 경계 검증은 의미가 있으나 범용 scope-complete 결론은 지원 불가. 실제 관찰 가능한 구체 사례가 추가될 때 재검토 |

## A를 다음 후보로 고른 이유

ER-D3의 별도 Semgrep feasibility 실험은 같은 Profile ID를 유지하면서 선택 파일 바이트가 바뀌는 경우 digest가 달라짐을 재현했고, 규칙 주석만 바꾼 두 사본의 Finding ID가 같을 수 있음을 확인했다. 이는 Profile ID만으로 파일 내용 동일성을 알 수 없음을 실증한다. A는 소스 원문을 수집하지 않고 규칙 파일에만 범위를 한정할 수 있어 B보다 데이터 노출 면적이 작다.

단, A의 결과는 “선택된 규칙 파일 사본의 관찰 바이트가 같거나 다르다”는 confounder 정보일 뿐이다. `loaded_rule_identity_unverified`는 계속 남아야 하며, digest 동일성을 실제 Semgrep loaded rule set 동일성으로 승격하지 않는다. 이 제한 때문에 Evaluator의 Finding 소멸 원인을 자동 확정해서는 안 된다.

## ER-D6 설계 Gate

구현 전에 다음을 만족해야 한다.

1. Semgrep에 전달되는 규칙 입력을 같은 안전한 사본에서 digest 및 실행에 연결하는 방법과 TOCTOU 잔여를 정의한다.
2. Registry TTL 안에서만 digest 또는 파생 equality 상태를 보유하고, API/UI/로그/Export에서 원시 digest를 노출하지 않는다.
3. 기존 `rule_bytes_unverified`를 어떤 조건에서만 제한적으로 해제할지 정의하고, `loaded_rule_identity_unverified`를 유지한다.
4. C1 Manifest v1 strict serialization과 C2 Evaluation v1을 수정 없이 유지할 수 있는지 확인한다. 필드/enum 의미 변경이 필요하면 버전 마이그레이션을 별도 승인 전까지 보류한다.
5. same bytes, changed bytes, comment-only change, read/replace race, symlink, permission, Semgrep failure를 검증한다.
6. 비교 결과가 계속 `UNDETERMINED`인 경우와 Rule Profile mismatch 차단을 확인한다.
7. 개인정보 리뷰와 프로세스 메모리/Registry byte budget 영향을 측정한다.

## 선택하지 않은 후보와 보류 이유

- **B**: 별도 소스 digest는 Semgrep 입력의 동일성을 증명하지 않고, Finding 원인도 증명하지 않는다. 프라이버시와 변경 경쟁 위험이 더 크다.
- **C**: 현재 검증된 ignore reason은 이미 수집된다. 새로운 reason은 Semgrep 출력의 구체적인 지원 사례와 안정된 의미가 입증될 때만 allowlist에 추가한다. Scope completeness를 넓게 주장하지 않는다.

## 변경·비변경 경계와 롤백

ER-D5에서 제품 코드/API/기존 규칙/Manifest/Evaluation 계약은 변경하지 않는다. ER-D6에서는 별도 prototype 및 설계 검토부터 진행하고, API 공개는 별도 검토한다. 구현이 원시 digest 외에는 유용한 정보 제공을 못 하거나 C1/C2 버전 변경 없이는 엄밀한 연결이 불가능하면 A 선정은 철회하고 `ER_D6_IMPLEMENTATION_SELECTION_HOLD`로 전환한다.

프로토타입 롤백은 해당 internal evidence capture 경로를 제거하고 기존 limitation을 다시 항상 유지하는 방식이어야 한다. 기존 Finding 결과·ID·일반 검사에는 영향이 없어야 한다.

## 미승인 상태

- ER-D6 코드 구현: 미승인
- Manifest/Evaluation 공개 계약 변경: 미승인
- 다중 Worker/사용자 및 운영 배포: 지원되지 않음/승인되지 않음
- 실제 사용자 판단 효과: 미검증
