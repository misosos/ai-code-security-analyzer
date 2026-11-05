# Finding 변화 조사: 분석가 판단 워크플로

이 절차는 재검사에서 Finding ID가 달라졌을 때 관찰, 해석, 한계, 후속 조치를 순서대로 정리한다. 서버가 Finding의 수정 또는 해결 여부를 자동으로 종결하지 않는다.

## 1. 기준 검사 확인

1. 조사 모드에서 기준 검사를 실행하고 ScanResponse와 서버 Evidence Handle이 같은 응답에서 왔는지 확인한다.
2. 대상과 Rule Profile, Semgrep 버전, `scan_status`, 완료 여부, omitted Finding 수를 확인한다.
3. 부분·실패·생략 결과라면 완료된 Finding 부재로 해석하지 않는다.
4. 기준 Snapshot만으로도 Finding ID, 규칙 ID, 상대 파일 위치 등 응답의 검증된 정보를 기록할 수 있다.

## 2. 현재 검사 실행

1. 같은 프로젝트와 의도한 Profile로 재검사한다.
2. 두 검사가 각각 정상 완료했는지, Finding 생략이 없는지 확인한다.
3. 결과를 분석가가 선택한 기준과 비교하고 현재 검사 결과가 다른 비동기 요청으로 바뀌지 않았는지 확인한다.

## 3. Finding 변화 분류

- `shared`: 같은 Finding ID가 두 응답에 있다. 같은 코드 내용·실행경로·보안 상태를 뜻하지 않는다.
- `baselineOnly`: 기준에 있던 ID가 현재 응답에 없다. 수정·해결·안전을 뜻하지 않는다.
- `currentOnly`: 현재 응답에서만 ID가 보고됐다. 새 취약점 발생을 뜻하지 않는다.

이는 의미상 취약점 추적이 아니라 Finding ID의 정확한 집합 비교다.

## 4. Evidence Investigation 확인

두 조사 Run의 Handle을 사용해 Session을 만들고 Evaluation을 요청한다. API는 같은 Run, 다른 대상/Profile, 해제·만료 증거 등을 거부한다. 성공한 Session은 관찰 비교가 가능하다는 뜻이지 분석 조건의 완전한 동일성을 뜻하지 않는다.

`baselineOnly` Finding에서 다음을 확인한다.

1. `path_observation`: 현재 Semgrep이 해당 경로를 처리했다고 보고했는지, 명시적으로 Skip했다고 보고했는지, 경로/Skip 근거가 없거나 충돌하는지.
2. `skip_hypothesis`: 고정된 경로 근거가 Skip 설명을 지원·반박하는지, 판단할 수 없는지.
3. `source_snapshot_hypothesis`: 코드 Snapshot을 수집하지 않은 한 코드 변경을 평가하지 못함을 확인한다.
4. `rule_identity_hypothesis`: 선택된 Rule Profile과 실제 규칙 바이트/로딩 집합 확인을 구분한다.
5. `limitation_codes`: Scope 완전성 미검증, 생략, incomplete 등 추가 한계를 확인한다.
6. `comparability`와 `overall_assessment`: 서로 다른 상태다. 관찰이 비교 가능해도 전체 원인은 `UNDETERMINED`일 수 있다.

`PATH_REPORTED_SCANNED`는 경로 처리 보고만 의미한다. 모든 규칙이 완료됐다는 증거가 아니다. `PATH_EXPLICITLY_SKIPPED` 역시 검사 절차 관찰이며 취약점 해결의 원인이 확정됐다는 뜻이 아니다.

## 5. 후속 확인과 판단 보류

필요한 경우 분석가가 별도로 다음 자료를 확인한다.

- 코드 이력과 Git Diff, 파일 이동·삭제 여부
- 현재 소스와 실제 입력·호출 경로
- 적용된 규칙 파일, 규칙 버전과 ignore 설정
- 두 검사 시점의 실행 환경 및 검사 완료 상태
- 동일한 조건에서의 재검사
- 별도 수동 보안 영향 검증

이 작업을 조사기가 이미 수행했다고 기록하지 않는다. 직접 연결된 증거가 없으면 가능한 설명을 가설로 남기고 원인 판단을 보류한다.

정상 0 Finding도 안전성 증명이 아니다. `INCOMPARABLE`, evidence unavailable, HTTP 오류는 정상적인 빈 Evaluation과 구분한다.

## 6. Evidence 해제

분석을 마치면 Session을 먼저 해제하고 더는 참조되지 않는 Run을 해제한다. UI 또는 API Release는 명시적 정리 요청이며 물리 메모리의 즉시 완전 삭제를 증명하지 않는다. 요청이 전달되지 않거나 프로세스가 재시작되면 복구되지 않으며, 서버의 절대 TTL은 최대 15분이다.

## 관련 자료

- [평가 설계](er-d2-analyst-workflow-evaluation-design.md)
- [평가 결과](er-d2-analyst-workflow-evaluation-results.md)
- [재현성 기록](er-d2-reproducibility-record.md)
- [ER-D1 Finding 소멸 사례](case-studies/finding-disappearance-investigation.md)
