# ER-D7 Rule Bytes Evidence Integration

## 목적과 경계

ER-D7은 ER-D6의 선택 규칙 파일 사본을 실제 조사 Run에 연결한다. 기능은 명시적으로 선택한 `POST /api/v2/investigation-scans/rule-bytes`에서만 활성화된다. 일반 v1 검사와 기존 v2 조사 검사는 변경하지 않는다.

## 실행과 Run Binding

`ScanService._scan_with_rule_bytes_manifest()`는 등록된 Target과 baseline Profile을 다시 검증하고, ER-D6이 고정한 사본으로 Semgrep을 한 번 실행한다. 그 한 실행의 `_ScanOutput`으로 ScanResponse와 Manifest를 만들고, 같은 bound object에서 `rule-bytes-observation/v1`을 만든다. 별도 Semgrep 실행 결과를 결합하지 않는다.

Manifest v1 필드는 그대로 유지하며 invocation은 닫힌 값 `semgrep-json-investigation-rule-bytes-v1`로 구분한다. Observation은 `scan_ref`, Target, Profile, invocation, Semgrep version과 private digest를 갖는다. 외부 요청은 Digest, Rule Path, invocation 또는 Semgrep option을 제출할 수 없다.

## Registry와 수명

`register_rule_bytes_run()`은 기존 Response/Manifest binding과 Observation binding을 모두 검증한 뒤 Run payload와 32-byte sidecar를 원자적으로 등록한다. sidecar는 기존 Run의 절대 TTL(최대 900초), 최대 Run 4개, Registry 전체 byte cap, Session pin과 Release 정책을 공유한다. Run 만료·Release 시 함께 제거되며 프로세스 재시작 뒤 복구되지 않는다. 등록 실패는 Run을 남기지 않는다.

## Equality Projection

`POST /api/v2/investigations/rule-bytes/evaluate`는 기존 Session Handle만 받는다. 응답 `rule-bytes-comparison/v1`은 `SAME_SELECTED_BYTES`, `DIFFERENT_SELECTED_BYTES`, `UNVERIFIED`, `INCOMPARABLE` 중 하나와 고정 limitation 두 개만 반환한다. Digest, 규칙 내용, Scan Reference, 경로와 raw Semgrep output은 반환하지 않는다.

부분 검사나 실행 실패는 `UNVERIFIED`다. 다른 invocation, Target/Profile, Semgrep version 또는 동일 Run은 기존 Session/문맥 Gate나 `INCOMPARABLE`로 차단된다. 같은 바이트는 선택된 단일 파일 사본만 뜻하며 loaded rule inventory, 모든 규칙 적용, 소스 동일성 또는 취약점 해결을 뜻하지 않는다.

## UI와 기존 계약

조사 모드의 `규칙 파일 동일성 증거 포함`은 기본 OFF다. 활성화 상태가 다른 두 Run은 클라이언트에서도 결합하지 않는다. 결과 패널은 별도 규칙 바이트 비교를 표시하며 기존 Finding Evaluation v1의 `rule_bytes_unverified`와 `loaded_rule_identity_unverified` 의미를 바꾸지 않는다. Analyst Review, Memo 및 Export에는 Handle이나 sidecar가 포함되지 않는다.

## Rollback

신규 두 API route, sidecar 등록/평가, ScanService opt-in 메서드와 UI checkbox를 제거하면 기존 v1과 기존 v2 계약으로 복귀한다. Manifest/Evaluation v1 wire shape에는 rollback migration이 필요하지 않다.
