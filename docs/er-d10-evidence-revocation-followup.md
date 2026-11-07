# ER-D10 후속: 증거 해제 검증과 부분 검사 안내 정합성

## 기준과 범위

시작 HEAD는 `f278043a14c72e5674c51aa5153cbef2e2dd10d4`, 브랜치는 `research/er-d10-safari-acceptance`였다. 추적 변경은 없고 미추적 `.taste-skill/`이 있었다. origin/main `6fc6ce98b914d3727296b539b4e27a4f3f186cd0` 대비 ahead 1 / behind 0이었다. 기존 로컬 준비 커밋을 보존하고 `research/er-d10-evidence-revocation-followup`의 별도 Worktree에서 수정했다. 시작 원격 성공 CI `42320362463`은 원격 기준 커밋의 결과이며 이번 변경의 CI가 아니다.

Desktop 원본은 main `c783d2d7f37115289f8fc9d953bcf70b242809de`에 기존 추적 변경과 미추적 자료가 있는 상태로 보존했다. 해당 원본을 checkout·reset·stash하지 않았다. 사용자 4173 listener도 같은 프로세스로 유지되고 있다.

[사용자 수용 기록](er-d10-analyst-acceptance-results.md)에 2026-11-07의 7개 UI 동작 PASS를 사용자 진술 그대로 반영했다. 서버 동작 및 이번 수정 후 Safari 수용으로 확대하지 않는다. `secure-development`, `security-validation`, `security-report`의 근거·실패·미검증 구분을 적용한다.

## 서버 생명주기: 실제 구현

근거는 [Registry](../src/ai_code_security_analyzer/investigation_evidence_registry.py), [API 경로](../src/ai_code_security_analyzer/api/routes.py), [앱 구성](../src/ai_code_security_analyzer/api/app.py), [닫힌 요청 스키마](../src/ai_code_security_analyzer/api/schemas.py)다.

- 각 API 앱 인스턴스의 Process-local Registry가 직렬화된 Run 응답·Manifest와 별도 규칙 바이트 sidecar를 관리한다. Run 최대 4개, Session 최대 2개이며 기존 용량 제한을 유지한다. 재시작 복구와 다중 사용자 격리는 지원하지 않는다.
- Handle은 `secrets.token_urlsafe(32)`로 만들며 43자 닫힌 형식이다. Registry 조회 키는 Handle의 SHA-256이다. 사용자에게 내부 Run Reference나 Digest를 반환하지 않는다. Session은 서로 다른 두 Run의 내부 참조와 Target/Profile 문맥에 결합된다. 인증된 POST body만 Handle을 전달한다.
- `POST /api/v2/investigation-release`의 kind가 Session이면 Session만 지운다. Run은 참조 Session이 남아 있으면 409 `binding_rejected`로 차단한다. 두 Session이 같은 두 Run을 사용할 수 있고 하나를 해제해도 다른 Session을 자동 해제하지 않는다. 다른 사용자의 권한 격리를 제공한다는 의미는 아니다.
- 정상 해제와 이미 없는 유효 형식 Handle의 반복 해제는 204다. 조회·평가·다시 Session 생성 시 없는 증거는 404 `evidence_unavailable`다. 잘못된 형식은 HTTP 요청 검증에서 400 `invalid_request`, 종류가 잘못된 Handle의 평가는 404다. kind를 바꾼 해제는 다른 종류의 레코드를 삭제하지 않고, 없는 kind의 레코드에 대한 idempotent 204가 된다.
- 평가 중 pin된 Session·Run의 해제는 409 `evaluation_busy`다. 평가는 완료 직전에도 같은 Session·Run이 남아 있고 만료 전인지 재확인한다. 내부 불가 상태는 503 `internal_unavailable`, 예기치 않은 예외는 세부정보 없는 500 `internal_error`다.

UI의 **비교 기준 해제**는 기준과 Session을 비우되 현재 검사와 같은 Run은 유지할 수 있다. **조사 증거 해제**는 Session과 보유 Run 모두의 해제를 요청한다. 새로고침으로 브라우저 상태가 초기화되는 사실은 서버 증거 해제의 증거가 아니다. 세 동작을 같은 서버 무효화 PASS로 취급하지 않는다.

### TTL의 정확한 의미

공식 앱은 기본 생성자로 Run/Session TTL을 각각 900초로 사용한다. Run 만료는 등록 시 `monotonic clock + 900`, Session 만료는 `min(Session 생성 + 900, 두 Run 만료)`다. 조회와 새 Session 생성은 기존 Run의 수명을 연장하지 않는다. `now >= expires_at`부터 접근을 거부한다. 내부 생성자는 다른 시계·TTL 값을 받을 수 있으나 공식 앱은 기본 900초를 사용하고 공개 API에 TTL 설정을 노출하지 않는다. 이번 시험은 시계만 주입해 기본 보존 상한을 검증했다.

TTL은 **접근 만료** 계약이다. 메모리에서 레코드를 치우는 작업은 요청 또는 `cleanup_expired()` 때 실행되며, 평가 중 pin된 레코드는 작업이 끝날 때까지 참조될 수 있다. 유휴 서버의 메모리가 정확히 900초에 자동 삭제되거나 Python 메모리가 즉시 안전하게 덮어써진다고 보장하지 않는다. 원래 아키텍처에 주기적 청소나 동기식 전체 해제 보장을 추가하지 않았다. UI의 “서버 메모리 최대 15분 보관”은 “생성 후 최대 15분에 접근 만료”로 고쳐 이 차이를 반영했다.

## UI 문제와 최소 수정

부분 기준을 저장하면 기존 comparator의 `same_scan_snapshot` 안내가 “같은 대상과 규칙으로 새 검사를 실행하면 결과 차이를 확인할 수 있습니다”라고 표시됐다. 같은 화면에 부분 검사 비교 차단이 있어 정상 비교를 약속하는 것처럼 보였다. 비교기의 분류·차단 계약은 유지하고, 부분 기준의 `same_scan_snapshot` / `current_missing` 안내만 다음과 같이 투영한다.

> 부분 검사 기준을 저장했습니다. 정상 결과 비교는 불가하며, 서버 조사에는 두 검사의 유효한 증거가 필요합니다.

정상 완료 기준의 새 검사 안내는 유지한다. 기준 없음은 정상 비교에 완료된 기준이 필요하다고 알리고, 다른 비교 불가 사유는 기존 고정 안내를 유지한다. 해제 이후에는 현재 Finding과 검토 상태·메모를 유지하며 서버 근거와 Map을 즉시 무효화한다.

원래 해제는 오류를 삼키는 best-effort였다. 이번에는 요청마다 5초 AbortSignal을 전달하고 확인 여부를 내부 boolean으로 반환한다. Session을 먼저 요청하고 각 Run 요청도 계속 시도한다. 해제 버튼은 즉시 “해제를 요청했습니다”라고 안내하며, 하나라도 확인되지 않으면 다음 경고를 접근 가능한 `role=alert`로 표시한다.

> 서버 증거 해제를 확인하지 못했습니다. 화면의 조사 근거는 지웠으며 현재 Finding은 유지됩니다. 서버 증거는 생성 후 최대 15분에 접근이 만료됩니다.

오래된 해제 결과가 새 검사·기준 변경 안내를 덮어쓰지 않도록 기존 요청 순번으로 검증한다. 네트워크 중단·Timeout은 서버가 실제로 처리했는지 알 수 없으므로 성공·실패의 서버 상태를 추측하지 않는다. 여러 요청은 전체 원자적 해제가 아니며 일부 성공이 가능하다. 실패한 Handle을 브라우저 저장소나 Export에 보관하거나 자동 재시도하지 않는다. 배경 정리도 계속 best-effort이고 서버 TTL은 최종 접근 만료 경계다.

## 검증 자료와 결과

[서버 후속 시험](../tests/test_evidence_revocation_followup.py)은 합성 ScanService와 실제 FastAPI/Registry 경로를 사용한다. A1 정상 조회, A2 해제 후 실제 저장 카운트·바이트 0, A3 반복·다른 Session·kind·미존재·잘못된 형식·재결합 거부, A4 기본 900초 직전/경계 시계 주입, A5 503/500 및 부분 성공을 검증한다. 실제 15분 대기는 하지 않는다. 기존 Registry의 평가 중 pin·해제 경쟁·sidecar 시험과 실제 Semgrep/API E2E를 함께 실행한다.

[UI 단위 시험](../frontend/tests/evidence-revocation-ui.test.tsx)은 정상/부분/기준 없음 안내, 해제 실패·Timeout·늦은 응답, 일부 해제 실패 시 나머지 요청과 Map 무효화를 검증한다. [브라우저 시험](../frontend/browser-tests/evidence-revocation.spec.ts)은 합성 HTTP 응답으로 Chromium/WebKit에서 부분 저장, 키보드 해제, 실패 경고, Finding·메모·검토 유지, 기준 해제와 새로고침을 확인한다. 이 자동화는 실제 Safari 사용자 조작이 아니다.

| 실행 범위·명령 | 실제 결과 |
| --- | --- |
| `PYTHONPATH=tests:. uv run pytest -q tests/test_evidence_revocation_followup.py` | 5 passed; 합성 서비스와 실제 API·Registry 계약 |
| `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests:. uv run pytest -q` | 680 passed / 28 skipped; 실제 Semgrep 통합·API·Registry·규칙 바이트 포함, 기존 Starlette 경고 1건 |
| Node 24 `npm run typecheck`, `npm test`, `npm run build` | 통과; Vitest 20 files / 219 passed, 새 UI 시험 7건 포함 |
| 포트 49601, `CI=1 npm run test:browser` | Chromium 56 passed; axe·키보드·비교·메모·Export·백업/복원 포함 |
| 포트 49602, `CI=1 npm run test:browser:webkit` | WebKit 3 passed; 새 실패·부분 안내·메모 유지·새로고침 포함 |
| `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24 -- npm run test:e2e:real` | 실제 FastAPI–Semgrep–Chromium 3 passed / 선택 시나리오 2 skipped; Skip·부분 비교 차단·Map·증거 해제·해제 후 404 포함 |
| `uv lock --check` | 통과 |

브라우저 명령은 `BROWSER_TEST_PREVIEW_PORT`를 설정하고 `mise exec node@24 --`로 실행했다. 기존 4173 서버를 재사용하지 않았다. 기존 스킵 28건을 PASS로 집계하지 않았고 시험을 삭제하거나 추가로 skip하지 않았다. 준비용 Safari QA 실행기 시험은 이번에 변경하지 않아 재실행하지 않았으며, 수정된 제품 UI는 위 회귀와 실제 E2E로 검증한다. 기존 백업/복원·Export·검토와 스캐너 의미는 유지한다.

### 초기 실패와 재실행

새 UI fixture가 비공개 `semgrep_skipped_paths`를 공개 issue로 사용해 닫힌 parser에서 거부됐다. 기존 공개 코드로 고쳐 검증을 유지했다. 초기 추가 시험의 검사 시작 화면 선택자도 결과 화면에만 존재하는 패널을 찾고 있어 실제 화면 경계에 맞췄다. 보안 기대값을 낮추지 않았다. 기존 실제 Semgrep Registry 시험은 초기 버전/도움말 probe 10초 제한에서 두 번 `timed_out`으로 실패했고, 단독 재실행에서는 통과했다. 제품의 10초 probe / 60초 scan 제한은 변경하지 않았다. 상세 부하 원인은 별도 계측하지 않았으므로 확정하지 않는다.

## 완료 판정

`ER_D10_FOLLOWUP_LOCAL_GO`. 성공 응답을 받은 해제의 재사용 차단, 기본 900초 접근 만료, 실패 시 로컬 근거 무효화와 경고, 부분 기준 안내 및 기존 흐름 회귀를 자동 검증했다. 검증된 변경만 후속 로컬 커밋으로 남긴다. 원격에 없는 기존 준비 커밋까지 보존하므로 origin/main 대비 로컬 커밋은 2개가 된다. 신규 원격 CI는 `PENDING_USER_PUSH`다.

## 한계와 후속

이번 변경의 실제 Safari 수동 재검수, VoiceOver·iOS는 `NOT_VERIFIED`다. 사용자 보고된 7개 UI PASS는 수정 전 수용 범위로 보존한다. 수정된 부분 기준 문구와 해제 실패 경고를 실제 Safari에서 다시 확인하도록 권고한다. 실제 프로세스 메모리의 안전한 소거, 유휴 상태의 정시 삭제, 네트워크 실패 시 서버가 요청을 처리했는지는 보장하지 않는다. 운영 승인은 `NOT_APPROVED`이며 Push는 수행하지 않는다.

기존 4173 서버는 이전 버전을 유지한다. 수정 후 수동 재검수는 새 터미널에서 아래의 격리 실행기를 사용한다. 주소와 Token은 사용자 터미널에서만 확인하며 채팅이나 기록으로 전달하지 않는다.

```bash
cd /tmp/ai-csa-er-d10-evidence-revocation-followup/frontend
mise exec node@24 -- npm run qa:investigation:safari -- --scenario=skip
```

실제 통신 실패를 만들려고 기존 사용자 서버를 중단하지 않는다. 실패 안내는 이번 합성 자동화로 검증했으며 실제 Safari 실패 조작은 별도 미검증이다.
