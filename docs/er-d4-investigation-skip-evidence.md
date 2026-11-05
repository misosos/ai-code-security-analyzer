# ER-D4 — Investigation Skip Evidence

## 목적과 변경 범위

ER-D4는 조사 API 실행에서만 Semgrep의 `--verbose` 출력을 요청해, C1이 허용한 `paths.skipped` path/reason을 수집한다. Finding이 현재 검사에서 보이지 않는 경우 해당 경로가 제외됐다는 제한된 검사 절차 관찰을 제공한다. 일반 `/api/v1/scans`와 CLI 기본 호출은 기존 Semgrep 인자 및 공개 응답 계약을 유지한다.

v2 조사 API는 내부 `ScanService._scan_with_manifest(..., investigation_verbose=True)` 경로를 사용한다. 요청자가 옵션이나 invocation ID를 지정할 수 없으며, 조사 외 경로는 verbose를 켜지 않는다. `--verbose`가 없는 지원 실행은 고정된 실행 실패로 닫힌다. 기존 timeout, stdout/stderr 합산 2,000,000-byte 한도, JSON/metrics/version/OSS/no-autofix 옵션과 trusted local rules/registered targets는 유지된다.

## 실행 정체성과 증거

기본 실행 ID는 `semgrep-json-local-v1`이고 조사 verbose 실행 ID는 `semgrep-json-investigation-verbose-v1`이다. 생성기, evaluator, strict Registry 복원은 닫힌 허용 목록을 검사한다. 기본 실행의 기본값은 바뀌지 않는다. 서로 다른 invocation ID를 가진 Run은 기존 비교 문맥 Gate에서 `INCOMPARABLE`로 차단된다.

Manifest는 기존 ScopeEvidence 계약을 재사용한다. `paths.scanned`, `paths.skipped`, `errors`, `skipped_rules`는 기존 경로 정규화, 상대 경로 및 traversal/symlink/NFC 충돌 검사, reason allowlist, 개수·바이트 제한을 통과한 구조만 보유한다. Raw Semgrep JSON, 자유형 stderr, 소스 코드, 절대 경로를 새로 저장하지 않는다. 누락된 `paths.skipped`는 “skip 없음”을 뜻하지 않는다. 모르는 reason이나 검증에 실패한 scope는 기존 unavailable/not-collected 상태로 남는다. Scope completeness는 계속 `UNVERIFIED`다.

## Partial과 평가 의미

유효한 non-empty `paths.skipped`는 기존 parser issue를 유지하고 Scan을 `PARTIAL`, `completed=false`로 만든다. 출력/파싱 오류, timeout, output limit, 비정상 종료는 정상 평가로 대체하지 않는다. Evaluator는 partial Run의 aggregate `comparability`와 `overall_assessment`를 `INCOMPARABLE`로 유지한다. 실제로 skip된 baseline-only 경로에는 Finding별 `PATH_EXPLICITLY_SKIPPED` 및 `SUPPORTED` 가설이 표시될 수 있다. 이는 Semgrep이 경로를 해당 사유로 제외했다고 보고했다는 의미만 갖는다. 코드 수정, 취약점 해결, 유일한 원인 또는 모든 규칙의 검사 완료를 입증하지 않는다.

## 부분 조사 기준 UX

Frontend는 조사 모드가 켜져 있고, v2 scan envelope를 검증했으며, ScanResponse와 Handle이 같은 Snapshot에 결합된 경우에만 partial 결과를 조사 기준으로 저장한다. 일반 v1 partial 기준 저장은 계속 차단된다. 일반 comparator의 partial/failed comparison 차단은 변경하지 않는다. 서버 평가 경로는 comparator가 오직 partial 상태 때문에 차단한 유효한 동일 문맥 Run 쌍만 허용하고, Finding ID/category partition을 두 Snapshot과 다시 대조한다. partial 결과 UI에는 일부 검사임과 aggregate 비교 불가 상태를 분명히 표시한다.

## 검증과 한계

실제 Semgrep 1.182.1 기반 FastAPI TestClient 및 Chromium E2E는 A/B 기준에서 `.semgrepignore`에 `retired.js`를 추가한 partial current Run을 만들었다. API/UI에서 B의 skip 관찰, A shared, current Finding의 분류, aggregate `INCOMPARABLE`, Release 후 재사용 거부를 확인했다. 상세 명령과 결과는 [ER-D4 security E2E acceptance](er-d4-security-e2e-acceptance.md)에 기록한다.

조사는 단일 Semgrep 버전·합성 JavaScript·allowlisted ignore reason에 한정된다. Verbose가 전체 scope, 모든 loaded rules, 각 파일의 규칙 적용 완료를 증명하지 않는다. Registry는 process-local, bounded, 최대 15분이며 단일 Worker 공식 Launcher를 전제로 한다. 다중 Worker/사용자 운영, 하드 RSS 상한, 취약점 해결 판정은 지원하지 않는다. 실제 macOS Safari 수동 검수는 이 Phase에서 수행하지 않았다.

## 롤백

`api/routes.py`의 조사 호출에서 `investigation_verbose=True`를 제거하고 새 invocation ID 사용을 되돌린다. 일반 v1 경로는 변경 대상이 아니다. 기존 Registry가 process-local이므로 배포 전 프로세스 재시작 시 기존 evidence는 복구되지 않는다.
