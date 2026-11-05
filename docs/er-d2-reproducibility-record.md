# ER-D2 재현성 기록

## 기준과 환경

- 평가 시작 SHA: `f409c23472a1ac0cb7c763108b60f11439003c43`
- 기준 Push CI Run: `42019791673` — push/completed/success, Python tests and CLI·React dashboard·Semgrep 1.182.1 integration 모두 success, Artifacts 0
- 실제 로컬: macOS, Python 3.12.7 (`uv run --locked`), uv 0.11.26, Semgrep 1.182.1, Node.js 24.22.2
- 입력: 임시 디렉터리의 합성 JavaScript, 저장소의 신뢰된 `rules/security-baseline.yml`
- 네트워크 규칙 다운로드·사용자 프로젝트·실제 토큰 사용 없음. API Token은 실행 시 CSPRNG로 만들어 메모리에서만 전달. 출력에는 Token/Run Handle/Scan Reference를 기록하지 않는다.

## 실제 Semgrep 하네스

저장소 루트에서 실행:

```bash
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python scripts/evaluate_er_d2_workflow.py
```

스크립트는 동적 Loopback 포트에 격리 Uvicorn 앱을 올리고 HTTP 클라이언트로 실제 API v2 조사 경로를 호출한다. 임시 대상에 `stable.js`와 `retired.js`를 만든 뒤 첫 검사를 실행하고, 이어 `retired.js`를 안전한 비매치로 변경하고 `added.js`에 매치 코드를 추가해 두 번째 검사를 수행한다. 두 응답의 Finding Projection을 기존 comparator의 Gate 및 집합 비교와 서버 Evaluation 양쪽에 사용한다. 별도 실제 Run Handle 출력은 하지 않는다. 종료 시 Session, Runs를 해제하고 소유한 서버 스레드, socket, 임시 디렉터리를 정리한다.

하네스는 두 번 실행해 같은 고정 Projection을 얻었다.

- 기본 비교: `shared: stable.js`, `baselineOnly: retired.js`, `currentOnly: added.js` — 각 1건
- Evaluation: `COMPARABLE`, 전체 `UNDETERMINED`
- `retired.js`: `PATH_REPORTED_SCANNED`, Skip 가설 `CONTRADICTED`, Source Snapshot/Rule Identity 가설 `UNDETERMINED`
- 제한: `source_snapshot_not_collected`, `rule_bytes_unverified`, `loaded_rule_identity_unverified`, `scope_completeness_unverified`, `scan_result_is_not_safety_proof` 등
- 정확한 연결된 current Manifest의 Skip 상태: `NOT_COLLECTED`
- 동일 Run Handle 비교: HTTP 409 `binding_rejected`
- Session Release 후 재평가: HTTP 404 `evidence_unavailable`

실험자가 코드 편집을 수행했다는 지식은 Evaluator 입력으로 제공하지 않았다. 결과의 자세한 비교는 [평가 결과](er-d2-analyst-workflow-evaluation-results.md)를 참고한다.

## 추가 시나리오 계층

Zero Finding/Incomplete는 실제 Semgrep 시나리오로 위장하지 않고 계약 테스트에서 확인했다.

```bash
PYTHONPATH=tests SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked pytest -q \
  tests/test_api_scan.py::test_partial_zero_findings_and_omission_are_explicit \
  tests/test_finding_disappearance_evaluator.py::test_no_finding_is_not_a_safety_statement_and_empty_difference_is_undetermined \
  tests/test_finding_disappearance_evaluator.py::test_incomplete_runs_remain_incomparable_even_with_positive_skip_observation
```

결과: 7 passed. 정상 0 Finding은 안전성 증명이 아니며, partial/omitted 결과는 완료 비교로 승격되지 않는다.

## 회귀 검증

| 명령/검증 | 결과 |
| --- | --- |
| `uv lock --check` | PASS |
| Python 전체 `uv run --locked python -m pytest -q -rs` | 646 passed, 28 skipped, 경고 1개, 633.06초 |
| CI Semgrep integration 파일 선택 그대로 (`ci.yml`의 12개 테스트 모듈) | 46 passed, 경고 1개, 329.49초 |
| 신규 시나리오 4개 contract test | 7 passed, 경고 1개 |
| `mise exec node@24 -- npm ci` | 완료, audit 0 vulnerabilities |
| Frontend `npm run typecheck` | PASS |
| Vitest 전체 | 18 files, 192 passed |
| Production build | PASS |
| Chromium Browser suite | 전용 Preview port에서 53 passed |
| Playwright WebKit | 전용 Preview port에서 2 passed |
| 실제 FastAPI–Semgrep–Chromium E2E | 3 passed, 43.3초. A/B→A/C 워크플로 포함 |
| 기존 Safari QA 자동 회귀 | 7 passed |
| 조사 Safari QA 자동 회귀 | 4 passed |

Python 전체에서 28개 선택 Ollama E2E 테스트는 사전조건이 없어 skip됐다. 실제 Safari, VoiceOver, iOS Safari 수동 시험은 ER-D2에서 수행하지 않았다.

### 브라우저 실행 정합성

첫 Playwright 전체 실행은 기본 Preview port `4173`에 이미 실행 중인 별도 Desktop Vite 서버를 재사용해 21건 실패했다. 포트 소유자가 기존 Vite 프로세스임을 확인했고 종료하지 않았다. 해당 실행은 잘못된 서버에 연결된 검증으로 무효 처리했다. 이후 `CI=1 BROWSER_TEST_PREVIEW_PORT=43179`로 전용 Preview를 띄워 실행했고 53건 모두 통과했다. WebKit도 고유 포트로 재실행해 2건 통과했다. 기존 QA 서버나 Desktop 프로젝트를 수정·종료하지 않았다.

## 자동 테스트와 사용자 평가의 구분

하네스가 측정한 것은 결정적 ScanResponse 차이, Evaluation 코드, API 차단 결과다. React comparator의 비교 계산을 실제 응답으로 projection했지만 사람의 브라우저 사용성 평가가 아니다. ER-D2에서는 참가자를 모집하거나 판단 시간·정확도·업무 효율을 측정하지 않았다.

평가 실행 측정 시간은 Semgrep/API/test 실행 시간이며 분석가 소요 시간이 아니다. 표본은 한 개의 합성 A/B→A/C 사례와 계약 테스트 사례로 제한된다. 전체 Python 및 CI 통합 회귀 결과는 기능 변경 회귀의 범위를 보여주며, 평가 결과의 통계적 일반화를 제공하지 않는다.
