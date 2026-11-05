# ER-D3 — ER-D4 Implementation Decision

## 결정

**ER-D4에서 `Scope Completeness Evidence` 자체를 완성한다고 주장하지 않고, 조사 전용 Semgrep 실행에서 allowlisted `paths.skipped` 관찰을 수집한다.**

선택 후보: `C — Scope Completeness Evidence`의 제한된 Skip-detail 부분

판정: `ER_D4_IMPLEMENTATION_CANDIDATE_SELECTED`

이 결정은 특정 경로의 Semgrep skip reason을 관찰하는 기능이다. 파일 전체 Scope 완전성, 모든 규칙 적용 여부, Finding 미관찰의 최종 원인, 취약점 해결을 판정하는 기능이 아니다.

## 선택 이유

실제 Semgrep OSS 1.182.1 실험에서 기본 호출은 ignored 파일을 `paths.scanned`에 넣지 않았고 `paths.skipped` 필드를 제공하지 않았다. 격리된 `--verbose` 호출은 동일 파일을 `semgrepignore_patterns_match` 이유와 함께 `paths.skipped`에 보고했다. 정상 처리 파일과 Finding projection은 기본 호출과 같았고 오류 및 skipped-rules count는 각각 0이었다. Scope completeness는 두 경우 모두 `UNVERIFIED`였다.

현재 C1 parser는 allowlisted skip 필드를 이미 검증하고, C2 Evaluator는 `PATH_EXPLICITLY_SKIPPED`와 skip hypothesis 상태를 이미 표현한다. C3C DTO와 Dashboard에도 해당 closed code와 메시지가 존재한다. 새 공개 Finding Evaluation 필드를 추가하지 않고 제한된 절차 관찰을 전달할 수 있다.

## 미선택 후보

### A — 선택 rule file bytes identity

실험은 same Profile ID에서 선택 YAML 바이트 변경을 실제 digest로 구분했고 Finding 결과는 같음을 확인했다. 다만 현재 Manifest/Evaluation DTO에는 digest 비교 상태를 안전하게 전달하는 필드가 없다. 이를 분석가가 볼 수 있게 하려면 Manifest/Registry strict serialization과 Evaluation contract/version, 프런트엔드 parser를 함께 바꾸어야 한다. Immutable config snapshot을 실제 Semgrep 입력으로 전달하지 않으면 path 재열기 TOCTOU가 남으며, 그 경우도 loaded rule inventory를 입증하지 않는다. ER-D4의 단일 기능으로는 선택 Scope 관찰보다 경계가 넓다.

### B — source change evidence

별도 pre/post source digest는 관찰 시점의 변경만 보여주며 Semgrep이 같은 바이트를 읽었다는 보장이 없다. 입력 고정, race handling, file inventory, digest 민감정보, Registry 용량·수명, 공개 계약 변경이 필요하다. 파일 변경과 Finding 소멸 사이의 인과는 digest만으로도 입증되지 않는다.

## ER-D4 목표 및 제한된 계약

### 목표

조사 모드에서 현재 실행 JSON에 존재하고 C1 allowlist 검증을 통과한 `paths.skipped` path/reason을 수집해 해당 path의 절차적 skip 관찰을 나타낸다.

### 실행·신뢰 경계

- 일반 `/api/v1/scans` 실행 인자와 응답을 변경하지 않는다.
- `/api/v2/investigation-scans`에만 조사 전용 verbose 실행 옵션을 적용한다.
- 사용자가 제공한 규칙·target이 아닌 기존 allowlisted local rule/profile과 등록 target을 사용한다.
- `--verbose`는 출력 옵션 추가일 뿐 Scope 완전성 증명이라고 부르지 않는다.
- stdout/stderr 합산 2,000,000 byte 제한, 기존 timeout, `--no-autofix`, `--oss-only`, metrics/version-check 정책을 유지한다.
- stderr의 자유형 텍스트, raw JSON, 원본 코드, 절대 경로는 Manifest/API/log에 추가하지 않는다. 상대 경로는 현재 C1 path validator 및 size/count cap을 거친다.

### 입력·내부 증거

- `ScanService`의 private 조사 실행 옵션은 호출 지점에서 명시적으로 지정한다. 환경변수만으로 무조건 verbose를 켜지 않는다.
- 실행 모드마다 고정 invocation ID를 분리한다. 예: 기본 `semgrep-json-local-v1`, 조사 verbose `semgrep-json-investigation-verbose-v1`.
- baseline과 current의 invocation ID가 다르면 기존 C2 비교 문맥 검증으로 fail closed 한다. 과거 기본 모드 Run을 조사 모드 Run에 이어 붙이지 않는다.
- Manifest에는 현재 C1 `ScopeEvidence` 형태로 scanned/skipped/errors/skipped_rules 상태와 한정 요약을 보존한다. reason allowlist를 임의 확장하지 않는다.
- Raw Semgrep JSON이나 stderr를 저장하지 않는다.

### 응답·평가

- `ScanResponse` field set과 `finding-disappearance-evaluation/v1` field set은 바꾸지 않는다.
- 조사 Response가 `PARTIAL`이면 그 상태와 `completed=false`를 그대로 전달한다. Skip 자료가 존재해도 `COMPLETED`로 승격하지 않는다.
- 현재 Evaluator가 partial/omitted scan에 적용하는 `INCOMPARABLE` aggregate를 유지한다. 유효하게 연결된 baseline-only row의 `PATH_EXPLICITLY_SKIPPED` 및 `SUPPORTED` 절차 가설은 그대로 표기할 수 있지만, 이 finding-level 관찰이 aggregate comparability를 바꾸지 않는지 통합 테스트로 고정한다.
- `EXPLANATION_SUPPORTED`를 취약점 해결로 표시하지 않는다. Skip reason은 “Semgrep이 이 경로를 해당 이유로 건너뛰었다고 보고” 수준으로 제한한다.

## UI 기준 저장 Gate

현재 Dashboard는 정상 완료 scan만 비교 기준으로 저장한다. 조사 verbose로 skip이 발생하면 ScanResponse가 `PARTIAL`이므로 기준을 설정할 수 없는 흐름이 생길 수 있다.

ER-D4는 이 문제를 해결하지 않고 기능을 완성했다고 판정할 수 없다. 조사 모드에서 partial Run을 기준으로 저장하는 UX를 추가한다면 다음을 모두 만족해야 한다.

1. 증거 Handle과 같은 응답의 Snapshot만 저장한다.
2. 명시적인 partial 안내와 `INCOMPARABLE` 가능성을 보여준다.
3. 일반 v1 기준 설정 규칙은 그대로 둔다.
4. 기존 브라우저 comparator의 blocked 상태를 억지로 comparable로 바꾸지 않는다.
5. 서버 Evaluation만 별도 표시하며 결과 Finding partition을 현재 Snapshot과 재검증한다.
6. 정상 Run과 partial Run 조합, partial Run 두 개 조합, baseline release 및 만료를 시험한다.

이 제한된 UX를 안전하게 완료하지 못하면 ER-D4 진입 또는 완료를 HOLD하고, baseline 허용을 조용히 넓히지 않는다.

## 기존 ER 호환성

- v1 API, 공개 `ScanResponse` 필드, Finding ID, 일반 Semgrep 옵션은 불변이다.
- C1 Manifest version과 C2 Evaluation v1은 유지한다. invocation ID는 실행 option set을 구분하는 값으로만 사용한다.
- v2 조사 API가 verbose에서 `PARTIAL`을 반환할 수 있음을 기존 closed `ScanStatus`로 표현한다.
- C2의 incomparability/limitation 의미는 바꾸지 않는다.
- 두 실행에서 수집한 기존 `paths.skipped` code와 UI message를 재사용한다.
- 하나의 API 프로세스, Run 4개/Session 2개, TTL 15분, Evaluation single-flight, 기존 rate limit을 유지한다.

## ER-D4 변경 후보와 검증

### 예상 최소 변경

- `src/ai_code_security_analyzer/semgrep_adapter.py`: 조사 전용 verbose 옵션, 고정 invocation mode 전달, stderr/output cap 유지
- `src/ai_code_security_analyzer/services/scan_service.py`: private 조사 호출 인자와 Manifest invocation ID 전달
- `src/ai_code_security_analyzer/api/routes.py`: v2 조사 scan만 verbose 모드 사용
- `src/ai_code_security_analyzer/scan_evidence_manifest.py`: invocation ID 명시 전달/검증이 필요할 경우 내부 타입 변경
- `frontend/src/app/App.tsx` 및 investigation UI: partial 조사 Run 기준 저장 제한 해결이 필요할 때만 최소 수정
- 관련 adapter/parser/manifest/evaluator/API/Frontend regression tests

이 목록은 후속 후보이며 ER-D3에서는 해당 파일을 수정하지 않았다.

### 필수 ER-D4 테스트 Gate

- Semgrep 1.182.1 actual JSON에서 `.semgrepignore` skip path와 allowlisted reason 확인
- 비-verbose v1 output, Finding set, exit options 불변 확인
- verbose finding projection 동일성 및 output bytes/timeout cap 확인
- unknown reason, malformed `paths.skipped`, path traversal, symlink, count cap fail closed
- skip 정보가 있어도 scope completeness `UNVERIFIED` 유지
- verbose run status `PARTIAL` 유지 및 Evaluation aggregate `INCOMPARABLE` 유지
- per-finding path observation만 공개 고정 코드로 반환
- 기본 invocation과 verbose invocation 혼합 비교 거부
- token, handle, raw JSON/stderr, absolute path 비노출
- v2 API 실제 Semgrep E2E 및 partial baseline/current UI workflow
- 기존 v1 API의 응답 field set, CLI/adapter, D1/D2 fixture 회귀
- 1.182.1 외 버전은 허용 계약을 별도 검증하지 않으면 미지원/미검증으로 둔다.

## Gate와 실패 동작

ER-D4에서 verbose JSON이 없거나 구조/경로/reason 검증에 실패하면 기존 C1 `NOT_COLLECTED` 또는 `UNAVAILABLE`을 반환하고 원인을 추정하지 않는다. timeout, output cap, nonzero exit, malformed JSON은 정상 비교로 대체하지 않는다. verbose 옵션이 Finding set 또는 v1 behavior에 예상치 못한 변화를 주거나 partial-status UI gate를 안전하게 처리할 수 없으면 기능을 켜지 않고 ER-D4를 HOLD한다.

## 롤백

조사 전용 호출의 verbose 옵션을 제거하고 v2 조사 실행을 이전 invocation ID로 되돌리는 단일 설정/코드 변경으로 롤백한다. Registry는 process-local 15분 TTL이므로 재시작 시 복구되지 않는다. 새 descriptor나 digest 저장이 없으므로 rollback을 위한 기존 evidence 마이그레이션은 없다. 일반 v1 실행은 이 변경 전후 동일하게 유지한다.

## 이번 단계에서 확정하지 않은 것

- 사용자가 skip evidence로 원인 판단을 더 정확히 하는지
- 업무 시간, 오판률 또는 만족도 개선
- 모든 Semgrep 버전 및 모든 ignore 경로의 출력 형태
- 실제 OS 파일시스템 전체의 검사 완전성
- loaded rule set 동일성
- 소스 변경 또는 취약점 해결 여부
- 여러 사용자/worker 또는 운영 배포 승인
