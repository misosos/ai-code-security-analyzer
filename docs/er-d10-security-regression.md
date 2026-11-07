# ER-D10 보안 회귀 및 검수 환경 준비 기록

## 시작 Gate

`ER_D10_START_GATE_GO`. GitHub main과 origin/main은 `6fc6ce98b914d3727296b539b4e27a4f3f186cd0`이다. 정확한 CI [42320362463](https://github.com/misosos/ai-code-security-analyzer/actions/runs/42320362463)는 해당 head SHA의 push / completed / success이며 Python tests and CLI, React dashboard, Semgrep 1.182.1 integration이 각각 success, Artifact는 0개다. 이 원격 성공은 새 로컬 커밋의 CI 결과가 아니다.

Worktree는 `research/er-d10-safari-acceptance`다. 기존 Desktop의 추적·미추적 변경은 보존했다. 기존 4173 listener가 존재함을 확인했고 테스트는 별도 동적 또는 명시한 고유 포트를 사용한다.

준비 호스트는 macOS 15.7.7 / arm64, Python 3.12.7, uv 0.11.26, Semgrep OSS 1.182.1, Node.js 24.22.2다. 이 호스트 정보는 사용자가 실제로 Safari에서 수행한 버전·환경 기록을 대신하지 않는다.

## 변경과 보안 경계

QA 실행기에만 `--investigation --scenario=skip`을 추가했다. 사용자 Enter 후 QA 소유 합성 Target의 `.semgrepignore`만 변경한다. 별도 실 Semgrep smoke는 기준 완료 두 Finding, 현재 부분 검사 한 Finding, 제한된 Skip 관찰, aggregate INCOMPARABLE, Rule Bytes UNVERIFIED와 해제 후 두 평가 API의 404를 검증한다. 조사 외 실행에서는 Skip 옵션을 거부한다. 기존 A/B→A/C 실행은 유지한다.

대화형 터미널에 실행 Git SHA·추적 변경 여부를 표시한다. 이번에 안내하는 조사 QA의 Token은 실제 TTY에서만 표시하고 smoke·비대화형 출력에는 남기지 않는다. PTY 테스트가 캡처한 Token은 메모리에서만 사용하며 로그로 출력하지 않는다. 기존 단일 Worker, Target/Profile allowlist, 인증·Origin, Registry 크기·TTL·Release와 공개 DTO는 변경하지 않았다. 4173은 포트 할당에서 명시적으로 제외했다. SIGINT·SIGTERM·소유 서버의 비정상 종료에서 소유 자료만 정리하는 검증을 수행한다.

## 자동 검증 결과

자동화 결과는 [수동 수용 기록](er-d10-analyst-acceptance-results.md)의 PASS가 아니다.

| 명령·범위 | 실제 결과 |
| --- | --- |
| `uv sync --locked --group dev`, `uv lock --check` | 성공 |
| Node 24 `npm ci` | 성공; dependency install script 정책 안내가 있었고 설치 실패는 없었음 |
| Node 24 `npm run typecheck`, `npm test`, `npm run build` | 성공; Vitest 19 files / 212 passed |
| `BROWSER_TEST_PREVIEW_PORT=49501 mise exec node@24 -- npm run test:browser` | Chromium 55 passed; axe·키보드·반응형·Invalid/Stale 및 Gap Map 검증 포함 |
| `BROWSER_TEST_PREVIEW_PORT=49502 mise exec node@24 -- npm run test:browser:webkit` | WebKit 2 passed |
| Node 24 `npm run test:qa:investigation:safari` | 6 passed; 실제 두 시나리오, 비TTY Token 차단, 닫힌 옵션, PTY Enter·종료·정리, 버전 실패 검증 |
| Node 24 `npm run test:qa:safari` | 기존 Safari QA 자동화 7 passed |

### 실패와 재실행

초기 `SEMGREP_REQUIRED=1 PYTHONPATH=tests:. uv run pytest -q`는 4 failed / 671 passed / 28 skipped였다. 브라우저 회귀가 병행된 초기 구간에서 `test_api_semgrep_e2e.py`의 두 시험, `test_command_injection_hardening.py` 및 `test_command_injection_phase6f.py`의 각 한 시험이 실제 Semgrep `timed_out`으로 실패했다. 실패를 정상 결과로 바꾸지 않았다.

브라우저 작업이 끝난 뒤 아래 단독 재실행은 7 passed였다. 외부 부하와의 인과를 별도로 계측하지 않았으므로 확정하지 않는다. 제품 코드, 규칙, 기대값 또는 실행 제한 시간은 변경하지 않았다. Adapter 자체도 기존처럼 metrics와 version check를 비활성화한다.

```bash
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests:. \
  uv run pytest -q tests/test_api_semgrep_e2e.py tests/test_command_injection_hardening.py tests/test_command_injection_phase6f.py
```

전체 단독 재실행은 아래 명령으로 **675 passed / 28 skipped**, 기존 Starlette `BlockingPortal` deprecation warning 1건이었다. Semgrep Integration, 조사 API, Rule Bytes Evidence, Manifest·Registry·Evaluator 검사가 이 전체 묶음에 포함된다. 건너뛴 검사는 PASS로 집계하지 않는다.

```bash
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests:. uv run pytest -q
```

실제 FastAPI–Semgrep–Chromium은 다음 명령으로 3 passed / 선택 시나리오 2 skipped였다. 일반 검사와 조사 Skip·Partial 흐름, Map의 제한 안내와 해제 후 Session 404를 확인한다. 선택 시나리오가 건너뛰어졌다는 사실을 숨기지 않는다. `D8_GAP_CASE=same`을 명시한 별도 실행은 1 passed로, 두 정상 완료 조사 Run의 선택 규칙 바이트 동일성 및 A/B→A/C Map을 확인했다. 모두 합성 자료의 자동 Chromium 검증이다.

```bash
cd frontend
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24 -- npm run test:e2e:real
D8_GAP_CASE=same SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24 -- npm run test:e2e:real
```

추가 준비 검사는 `node --check` 두 QA 스크립트, 문서 상대 링크·민감정보 패턴, `git diff --check` 및 `git diff --cached --check`다. 새로운 실제 Safari 캡처는 생성하지 않았다. 기존 자동 브라우저가 이 격리 Worktree에서 재생성한 추적 캡처는 기준 내용으로 복원하고, 미추적 QA 자료는 보존·미스테이징한다. Backend·Frontend 제품 코드, trusted rule 원본 및 기존 CI Workflow 변경은 없다.

## 준비 판정과 Git

준비 판정은 `ER_D10_SAFARI_MANUAL_QA_PREPARED_LOCAL_CONDITIONAL_GO`다. 관련 QA 도구·테스트 두 파일과 문서 세 파일만 로컬 커밋한다. 부모는 시작 SHA이며 원격 main은 변경하지 않는다. 새 로컬 커밋의 원격 CI는 `PENDING_USER_PUSH`다. 실제 수동 수용 판정은 아직 부여하지 않는다.

## 수동 검수와 운영 한계

실제 Safari 사용자 조작·이해 평가, 실제 200% 확대·VoiceOver·iOS·실제 TTL 대기 검수는 수행하지 않았다. `SAFARI_MANUAL_ACCEPTANCE_PENDING`, `ANALYST_ACCEPTANCE_PENDING`을 유지한다. 기본 준비 시나리오는 합성 자료이며 EJS 원본의 수동 검수라고 주장하지 않는다. 운영 배포는 `NOT_APPROVED`다.
