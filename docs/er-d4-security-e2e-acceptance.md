# ER-D4 — Security E2E Acceptance

## 시작 Gate와 환경

- 기준 SHA: `c982c2431c9e3b96624b0d73390978c361b8b992`
- 시작 push CI: GitHub Actions Run `42043227591` — push/completed/success; Python tests and CLI, React dashboard, Semgrep 1.182.1 integration 성공; artifact 0
- Worktree: `/tmp/ai-csa-er-d4-investigation-skip-evidence`
- 입력: 격리 임시 디렉터리의 합성 JavaScript와 trusted local baseline rules
- Semgrep: OSS 1.182.1
- Python: 3.12.7; Node: 24 (`mise`)

원격 main, `origin/main`, 기준 SHA가 일치했고 정확한 CI Run을 확인한 뒤 작업을 시작했다. Desktop 프로젝트와 기존 QA 서버는 변경·종료하지 않았다.

## 구현 결과

- 일반 v1 경로는 기존 `_scan_with_evidence()` 기본 호출을 사용해 verbose 옵션을 추가하지 않는다. v1 DTO/ScanResponse는 변경하지 않았다.
- v2 조사 scan만 `--verbose`를 선택하며 실행 identity는 `semgrep-json-investigation-verbose-v1`이다. 기본 identity는 `semgrep-json-local-v1`로 유지한다.
- 기존 parser/C1 validator가 allowlisted `paths.skipped`를 검증하고 issue를 만든다. partial status를 성공으로 승격하지 않는다.
- partial pair의 일반 브라우저 비교는 계속 차단된다. 증거와 동일 실행인 조사 Snapshot만 기준으로 보존할 수 있고, 서버 Evaluation은 aggregate `INCOMPARABLE`을 유지한다.

## 실제 Semgrep API E2E

테스트 `test_investigation_api.py`의 실제 Semgrep 시나리오는 다음을 확인했다.

1. v2 조사 검사 A/B: `stable.js`, `retired.js` Finding을 가진 completed baseline.
2. `.semgrepignore`에 `retired.js` 추가 후 재검사: `stable.js`만 Finding이 보고되고 Run은 `partial`, `completed=false`.
   Registry의 검증된 내부 ScopeEvidence는 `retired.js`와 `semgrepignore_patterns_match`를 담고, invocation은 `semgrep-json-investigation-verbose-v1`이다. `completeness_status`는 `UNVERIFIED`로 남는다.
3. 같은 Target/Profile의 별도 Run Handle로 Session 생성.
4. evaluator 결과에서 retired Finding은 `baselineOnly`, 경로 관찰은 `PATH_EXPLICITLY_SKIPPED`, skip hypothesis는 `SUPPORTED`; aggregate 비교가능성과 전체 평가는 `INCOMPARABLE`.
5. `source_snapshot_not_collected`, `scope_completeness_unverified` 제한 유지.
6. Session/Run Release 후 옛 Investigation Handle 재사용은 404 `evidence_unavailable`.

원시 Semgrep JSON은 API 응답에 없고, 합성 소스 문자열도 Evaluation 응답에 나타나지 않았다.

## 실제 FastAPI–Semgrep–Chromium E2E

명령:

```bash
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  mise exec node@24 -- npm run test:e2e:real
```

테스트 하네스는 동적 loopback 포트, CSPRNG token, 한 Worker 및 임시 합성 Target을 사용한다. 조사 시나리오 전용 Target을 분리해 앞선 브라우저 테스트의 파일 변경이 기준 검사에 섞이지 않게 했다. 통과 결과: Playwright Chromium `3 passed`; 실제 API/Semgrep 조사 흐름에서 partial 상태, comparator 차단, 조사 `INCOMPARABLE`, Finding별 skip 관찰, Release 및 Handle 재사용 거부를 확인했다. Playwright 자동화 결과는 실제 macOS Safari 수동 수용으로 간주하지 않는다.

## 실패 및 보완 이력

- 첫 브라우저 E2E는 stale `frontend/dist`가 없어 앱 요청이 404가 되어 두 테스트에서 실패했다. Production build 후 재실행했다.
- 다음 조사 E2E는 앞선 시나리오가 같은 synthetic target에 만든 `added.js`가 조사 기준에 포함되어 실패했다. E2E harness에 조사 전용 합성 Target을 추가해 상태를 격리했다.
- 격리 수정 후 세 브라우저 E2E가 모두 통과했다. 기존 캡처가 기록되는 tracked 이미지가 테스트 중 갱신된 것을 확인하고 시작 버전으로 복원했다.

## 보안 의미와 남은 범위

- Finding 미관찰은 수정/해결 증거가 아니다.
- `PATH_EXPLICITLY_SKIPPED`는 제한된 Semgrep 절차 보고다. 모든 규칙의 분석 완료나 Scope 완전성을 뜻하지 않는다.
- invocation ID, rule bytes, loaded rule identity는 서로 다른 계약이다. 이번 변경은 실행 옵션 모드만 구분한다.
- 다중 Worker·다중 사용자 격리, 하드 RSS 제한, 15분 초과 보존, 실제 Safari/VoiceOver/iOS 수용은 미지원 또는 미검증이다.

## 테스트 실행 기록

- `uv lock --check` — 통과.
- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests uv run --locked --group dev python -m pytest -q` — 651 passed, 28 skipped, Starlette deprecation warning 1개. Semgrep integration 포함.
- Focused Registry/Manifest/Evaluator/API/Adapter 테스트 — 전체 pytest에 포함. 실제 Semgrep API scenario도 통과.
- `mise exec node@24 -- npm run typecheck` — 통과.
- `mise exec node@24 -- npm test -- --run` — Vitest 18 files, 196 passed.
- `mise exec node@24 -- npm run build` — 통과.
- `BROWSER_TEST_PREVIEW_PORT=43973 mise exec node@24 -- npm run test:browser` — Chromium 53 passed. axe 포함, 320px/390px 및 CSS viewport 200% 대리 검증 포함.
- `BROWSER_TEST_PREVIEW_PORT=43975 mise exec node@24 -- npm run test:browser:webkit` — Playwright WebKit 2 passed. 이는 macOS Safari 사용자 수용이 아니다.
- `mise exec node@24 -- npm run test:qa:safari` — 기존 Safari QA 자동화 7 passed.
- `mise exec node@24 -- npm run test:qa:investigation:safari` — 조사 QA 자동화 4 passed.
- 실제 FastAPI–Semgrep–Chromium E2E — 위 명령 실행에서 3 passed.
- 기존 `scripts/evaluate_er_d2_workflow.py` — ER-D4 전에는 `NOT_COLLECTED`를 기대해 첫 실행이 의도된 새 계약(`OBSERVED`)에서 실패했다. Harness를 현재 verbose 조사 경로의 사실에 맞게 갱신하고 재실행했다. 결과는 `COMPARABLE`/`UNDETERMINED`, B는 `PATH_REPORTED_SCANNED`/skip `CONTRADICTED`, 동일 Run 409, Release 후 404였다. 기존 ER-D2 역사 문서는 당시 결과를 그대로 보존한다.
- `scripts/research_er_d3_evidence_gaps.py` — 실제 Semgrep 1.182.1에서 A/B/C feasibility 결과 재현, trusted baseline 원본 불변.
- 전체 Playwright 최초 실행은 기본 port 4173에 이미 있던 사용자 소유 preview를 재사용해 21개가 실패했다. 해당 서버는 건드리지 않았다. 이 실행은 무효로 분류하고, 별도 포트 43973/43975에서 재실행한 통과 결과만 유효 회귀로 보고한다.
- 실제 macOS Safari 수동 QA, 실제 200% 확대, VoiceOver, iOS Safari — 수행하지 않음.
