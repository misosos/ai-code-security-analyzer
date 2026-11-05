# ER-D3 — Evidence Gap Technical Assessment

## 목적과 범위

이 문서는 ER-D2에서 남은 규칙 바이트, 소스 변경, 검사 Scope 증거 공백을 현재 코드와 Semgrep 1.182.1 합성 실험에 대조한다. 제품 코드, 공개 API, 기본 규칙은 변경하지 않았다. 결과는 ER-D4의 단일 구현 후보를 고르기 위한 기술 타당성 판단이다.

## 현재 데이터 흐름

`ScanService._scan_with_manifest()`는 allowlist에서 대상과 프로필을 확인한 뒤 `SemgrepAdapter._scan_with_evidence()`를 한 번 호출한다. Adapter는 `semgrep scan --json --metrics=off --disable-version-check --oss-only --no-autofix --config <selected-file> -- <target>`를 실행하고 같은 JSON 파싱에서 Finding과 제한된 `ScopeEvidence`를 만든다. 기본 실행에는 `--verbose`가 없다.

ScanService는 Response의 Finding ID·count·상태와 Manifest를 한 실행의 내부 쌍으로 묶는다. C2 `bind_run_evidence()`는 쌍의 값 일치를 확인한다. Registry는 직렬화된 정확한 쌍을 보유하고 evaluator에 전달한다. 공개 ScanResponse에는 Manifest, scan reference, rule digest가 없다. 일반 Finding 비교는 응답의 Finding ID 집합을 분류한다.

현재 Finding ID는 Semgrep rule ID, 상대 경로, 시작/끝 위치의 해시다. 코드 내용 해시나 의미적 Finding 동일성은 아니다. evaluator는 두 번의 Response/Manifest 바인딩이 맞는지 확인한 뒤 ID 집합 차이를 계산한다. 기준 전용 Finding의 현재 경로 처리 관찰을 찾을 수 있어도 코드 변경·취약점 해결을 판정하지 않는다.

## 후보 A — 선택된 규칙 파일 바이트 식별

### 현재 공백과 실험

Manifest의 `RuleEvidence`는 요청 Profile ID와 선택된 상대 rule file ID를 관찰한다. `byte_identity_status`와 `loaded_identity_status`는 모두 `UNVERIFIED`이며 C2 제한 `rule_bytes_unverified`, `loaded_rule_identity_unverified`를 보존한다.

실험은 신뢰된 `security-baseline.yml`을 격리 임시 폴더 두 곳에 복사했다. 두 검사 모두 같은 합성 대상, Profile ID `baseline`, 선택 파일 ID를 사용했다. 두 번째 사본에는 규칙 동작을 바꾸지 않는 YAML 주석만 추가했다. 실 Semgrep 1.182.1을 통해 두 검사는 완료됐고 Finding ID 투영은 같았다. SHA-256은 같은 사본에서 재현됐으며 주석이 추가된 바이트를 구별했다. 원본 저장소 규칙 파일은 변경되지 않았다.

### 가능한 추가 증거와 경계

선택된 설정 파일의 바이트 digest는 동일 Profile ID가 서로 다른 파일 내용을 가리키는 경우를 검출할 수 있다. digest가 다르면 선택 설정이 달랐다는 관찰을 지원하고, digest가 같으면 비교한 바이트 자료가 같았다는 관찰을 지원한다. 어느 쪽도 해당 바이트가 Semgrep에 성공적으로 로딩·적용됐거나 전체 loaded rule set이 같았음을 증명하지 않는다. 지금처럼 설정 파일 경로를 다시 열어 해시한 뒤 CLI가 별도로 경로를 열면 교체·복원 TOCTOU가 남는다.

강한 설계는 제한 크기와 symlink 정책을 적용해 읽은 정확한 바이트를 private immutable temporary config로 만들고, Semgrep에 바로 그 복사본을 전달해야 한다. 그래도 Semgrep 내부의 최종 loaded inventory, 버전별 처리, 규칙 적용 성공은 별도 관찰이다. digest를 외부에 노출하면 저엔트로피 규칙 내용의 추측 및 실행 간 상관 분석에 쓸 수 있으므로 기본 공개는 금지한다.

## 후보 B — 소스 변경 증거

### 현재 공백과 실험

일반 소스 Snapshot/digest는 Manifest에 수집되지 않는다. Manifest는 `source_snapshot_not_collected`를 고정 limitation으로 기록한다. adapter가 Firestore 특정 검증에 제한된 내부 사전 스냅샷을 쓰는 경로는 있지만, 이는 일반 소스 변경 기록이나 Run 간 Source Snapshot 계약이 아니다.

실험은 합성 `stable.js`와 `retired.js`를 기준 검사하고, `retired.js`의 `eval(input)`을 `String(input)`으로 바꾼 뒤 재검사했다. 실험용 스크립트는 변경 전·후 합성 파일의 digest가 달라졌음을 메모리에서 확인했다. 실제 Semgrep 결과에서 `stable.js` Finding은 양쪽에 있었고 `retired.js` Finding은 기준 검사에만 있었다. 그 digest는 Registry나 Manifest에 넣지 않고 출력하지 않았다.

### 가능한 추가 증거와 경계

파일 digest는 관찰한 두 읽기 시점의 바이트 차이를 나타낼 수 있다. 그러나 Semgrep이 해당 두 읽기와 같은 바이트를 열었는지, 파일이 검사 도중 바뀌지 않았는지, 그 변화가 Finding 미관찰을 일으켰는지 증명하지 않는다. 별도 pre/post read는 Semgrep 입력과 원자적으로 묶이지 않는다. 실행 입력을 증명하려면 파일 디스크립터 기반 안전 읽기, 파일 변경 감지 및 실제 검사 입력을 동일한 불변 복사본으로 고정하는 더 큰 변경이 필요하다.

파일 digest는 코드 원문보다 작아도 비밀이 아니라고 볼 수 없다. 흔한 코드나 설정의 사전 대입, 실행 간 링크, 파일명·경로와의 결합 위험이 있다. 여러 파일에 대한 저장은 Registry byte cap, 개인정보 정책, 삭제 수명, 결과 projection을 바꾼다. 이 증거가 있어도 Finding 원인을 단독 확정할 수 없다.

## 후보 C — Scope 관찰 확장

### 현재 공백과 실험

C1 파서는 `paths.scanned`, `paths.skipped`, `skipped_rules`, `errors`를 닫힌 제한으로 처리한다. `paths.skipped`에는 허용된 이유 코드 `semgrepignore_patterns_match`만 수용한다. 모든 실행에서 `completeness_status`는 `UNVERIFIED`다. 기본 제품 호출은 비-verbose이며 Skip 자료가 JSON에 없으면 `NOT_COLLECTED`다.

합성 JavaScript의 `normal.js`와 `.semgrepignore`에서 제외한 `ignored.js`를 실제 baseline 규칙으로 검사했다.

| 관찰 | 기본 제품 호출 | 격리 `--verbose` 호출 |
| --- | --- | --- |
| `paths.scanned`의 `normal.js` | 보고됨 | 보고됨 |
| `ignored.js`가 scanned에 없음 | 관찰됨 | 관찰됨 |
| `paths.skipped`의 `ignored.js` | 필드 미수집 | `semgrepignore_patterns_match`로 보고됨 |
| `errors` / `skipped_rules` 개수 | 0 / 0 | 0 / 0 |
| Finding ID·경로·규칙 ID 투영 | 기준값 | 동일 |
| Scope 완전성 | 미검증 | 미검증 |

실험은 현재 Adapter의 기본 비-verbose 호출과, 같은 Semgrep 옵션에 `--verbose`만 추가한 격리 호출을 비교했다. verbose JSON은 C1 `parse_scope_evidence()`에서 검증됐다. 파서는 비어 있지 않은 `paths.skipped`를 `semgrep_skipped_paths` issue로 보고한다. 현재 Adapter 상태 매핑을 적용하면 해당 응답은 `PARTIAL`이다. 따라서 verbose 정보가 있다고 불완전성 상태를 지우면 안 된다.

## 보안 및 계약 평가

| 후보 | 공백 감소 / 검증 가능성 | 소멸 원인에 주는 정보 | 보안 위험 | ER 영향 / 비용 | 결정 |
| --- | --- | --- | --- | --- | --- |
| A — 선택 rule bytes | 선택한 파일 바이트 비교는 강함, loaded set은 미검증 | 설정 drift 가능성을 좁힘. Finding 원인은 계속 미확정 | digest 상관·추측, 경로 재열기 TOCTOU | Manifest 직렬화/평가 결과 version 확장 필요, immutable snapshot 실행 설계 | 보류 |
| B — source digest | 별도 읽은 바이트 비교는 가능, 실제 Semgrep 입력 연결은 약함 | 코드 변경 존재를 좁힐 수 있어도 인과는 미확정 | 소스 유래 digest의 민감도, 파일 수·용량·보존 부담 | Scan 입력 고정·Registry 수명·공개 계약 변경이 큼 | 보류 |
| C — verbose Scope | Semgrep 1.182.1에서 일부 skip 이유를 실제 관찰, 재현 가능 | ignore 제외와 미관찰을 구분할 수 있음. 취약점 상태는 알 수 없음 | 추가 경로·stderr 및 출력량, 버전별 JSON 차이 | 기존 Scope/Evaluation/Frontend 코드 재사용 가능. `PARTIAL`을 유지하고 조사 API에서만 켜야 함 | ER-D4 우선 |

비교는 정량 점수 합산이 아니다. 각 판정은 위 실제 출력과 현재 코드 경로에 근거한다. A도 유용한 증거지만 현재 API v1의 닫힌 Evaluation DTO에는 바이트 비교 상태가 없다. A의 관찰을 분석가에게 전달하려면 새 closed result contract가 필요하며 digest 자체를 공개하지 않더라도 manifest/evaluation version migration을 해야 한다. B는 실행 입력과 바이트를 결합하는 문제 및 개인정보·수명 범위가 더 크다.

## ER-D4 선택

**선택: 조사 전용 실행에서 제한된 Semgrep Scope 상세를 수집한다.**

선택 이유는 실험에서 기본 호출로는 알 수 없던 특정 제외 경로와 allowlisted reason을 실제 Semgrep 출력에서 재현했고, 기존 C1 parser, C2 `PATH_EXPLICITLY_SKIPPED`, 공개 Evaluation v1 enum, UI 문구가 그 관찰을 표현할 구조를 이미 갖고 있기 때문이다.

선택은 조건부다. 구현은 v1 일반 검사 인자를 바꾸지 않고 `/api/v2` 조사 Scan에만 verbose를 적용해야 한다. 새 invocation ID를 쓰고 양 Run이 일치하는 호출 방식인지 검사한다. skipped path가 있으면 기존 파서의 `PARTIAL`을 그대로 보존한다. C2 평가 전체는 `INCOMPARABLE`이어도 finding별 skip 관찰을 반환할 수 있지만, 그 상태를 취약점 해결로 해석하지 않는다. 기본 비교가 차단된 상태에서도 조사 Panel이 현재 Finding 분류와 서버 평가를 분리해 보여주는 기존 흐름을 검증해야 한다.

현재 UI는 완료된 조사 Run만 기준으로 저장할 수 있다. verbose 수집 때문에 기준 Run이 `PARTIAL`인 실무 흐름도 필요하다면 ER-D4에서 조사 모드에 한해 부분 기준 보관을 명시적으로 설계·시험해야 한다. 일반 v1 baseline 허용으로 확대하지 않는다. 이를 안전하게 처리할 수 없으면 C 구현을 축소하거나 ER-D4 gate를 HOLD한다.

자세한 선택 결정과 ER-D4 계약은 [다음 구현 결정](er-d3-next-implementation-decision.md)을 참조한다.
