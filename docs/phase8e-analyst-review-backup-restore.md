# Phase 8E — 분석가 검토 기록 JSON 백업 및 안전한 복원

## 목적

분석가 검토 상태와 선택적 메모를 JSON 파일로 사용자가 직접 백업하고, 이후 검사에서 검증 후 참고하도록 한다. 백업 기록은 새 검사에 자동 승계하지 않는다. 가져온 JSON은 신뢰할 수 없는 입력으로 취급한다.

Markdown 검토 보고서는 사람이 읽고 공유하기 위한 문서다. JSON 백업은 지원되는 스키마를 검증한 뒤 현재 검사에 Finding 단위로 수동 적용하기 위한 구조화 자료다. 두 형식 모두 정식 CLI 보안 검토 보고서를 대체하지 않는다.

## 사용 흐름

1. 검사 결과 화면의 `검토 기록 백업 및 복원`을 연다.
2. `JSON 백업 다운로드`를 눌러 다운로드한다. 메모는 기본 제외된다.
3. 메모를 포함하려면 별도 선택하고, 다운로드 직전 민감정보 경고에 동의한다.
4. 이후 검사 결과에서 JSON 파일을 선택한다.
5. 파일 검증과 검사 문맥 일치 결과를 확인한다.
6. Finding별 현재/백업 상태와 메모를 검토한 뒤 적용할 항목에만 `이 기록 적용`을 누른다. 나머지는 건너뛸 수 있다.

파일 선택만으로 현재 기록은 변경되지 않는다. 적용으로 기존 수동 상태나 포함 메모를 덮어쓸 때는 별도 확인을 요청한다.

## JSON 스키마 v1

Schema identifier는 `analyst-review-backup/v1`이다. 고정된 최상위 키는 `schema_version`, `scan_context`, `findings`다. 검사 문맥에는 대상 ID, 규칙 프로필 ID, Experimental 여부, Semgrep 버전, 검사 상태, 브라우저 결과 수신 시각, 전체/표시/생략 Finding 수가 포함된다. Finding에는 ID, 규칙 ID, 상대 경로, 줄 번호, Severity, Finding 유형, 분석가 상태가 기록되며 메모는 선택 사항이다.

지원 상태는 `pending`, `needs_followup`, `reviewed`뿐이다. 백업은 API의 `verification_status`, `evidence_validation_status`, Severity 또는 근거 주장을 포함하거나 변경하지 않는다.

## 입력 검증 및 복원 조건

- 입력과 출력은 각각 최대 256 KiB다. 입력 크기는 파일을 읽기 전에 확인하며 초과 시 거부한다. 출력은 자르지 않고 전체 생성 결과가 제한을 넘으면 다운로드하지 않는다.
- UTF-8을 fatal 모드로 디코딩하고 잘못된 인코딩, JSON 문법 오류, 중복 JSON 키, 과도한 중첩을 거부한다.
- 허용 키와 타입을 정확히 확인한다. 알 수 없는 스키마/필드, 중복 Finding ID, 알 수 없는 상태, 2 KiB 초과 메모, 안전하지 않은 식별자/경로, 잘못된 개수와 50건 초과 항목을 거부한다.
- JSON 파싱 객체를 애플리케이션 상태에 병합하지 않고, 허용 필드만 새 객체로 복사한다. `__proto__` 등 알 수 없는 키도 스키마 검사에서 거부된다.
- 복원에는 현재 및 백업 검사 모두 정상 완료, 생략 Finding 0건, 같은 대상·규칙 프로필·Experimental 설정, 확인 가능한 같은 Semgrep 버전, 정확히 같은 Finding ID 집합, 각 Finding의 규칙/경로/줄/Severity/유형 일치가 필요하다.
- 일부 항목만 맞는 경우에도 일괄 부분 적용을 열지 않는다. 차단 이유를 표시한다.

모든 문맥이 일치해도 코드 원문이나 소스 스냅샷의 동일성은 증명되지 않는다. Finding ID 일치는 이전 검토가 현재 코드에 여전히 유효함을 뜻하지 않는다. 가져온 상태는 참고 기록이며 현재 보안 판정이 아니다.

정상 완료되지 않았거나 Finding이 생략된 결과도 현재 응답의 표시 범위를 보존하기 위해 백업할 수 있다. 이 백업은 복원 조건을 충족하지 않으므로 적용은 차단된다.

## 메모와 개인정보 보호

메모는 기본적으로 백업 JSON에서 제외한다. 포함을 선택하면 다운로드 직전 브라우저 확인 대화상자를 다시 표시한다. 사용자는 내부 코드 정보나 민감정보가 포함될 수 있고, 다운로드된 파일은 디스크에 남는다는 점을 확인해야 한다. 검토 상태와 메모는 브라우저 메모리에만 있고 JSON은 사용자 클릭으로만 다운로드한다.

업로드 파일은 브라우저 안에서만 읽고 외부 서비스나 API로 전송하지 않는다. 서버 저장, localStorage, sessionStorage, IndexedDB, 자동 동기화는 사용하지 않는다. 새 검사 시작과 결과 삭제는 복원 미리보기를 지운다. 파일 읽기 중 검사 결과가 바뀌면 해당 미리보기는 무효가 된다. 새로고침은 메모리의 상태와 미리보기를 소멸시키지만 이미 다운로드한 백업 파일은 삭제하지 않는다.

메모는 React 일반 텍스트로만 표시하며 HTML/Markdown으로 실행하지 않는다. JSON에는 API 토큰, 원본 코드, 절대 경로, HTTP 원문, 환경변수, stderr를 포함하지 않는다. Markdown 보고서 내보내기는 이번 백업을 자동 포함하지 않는다.

## 변경 범위

- `frontend/src/features/scans/analystReviewBackup.ts`: 결정적 백업 생성, 제한된 JSON 파싱, 문맥/메타데이터 복원 검사, 사용자 클릭 다운로드.
- `frontend/src/app/App.tsx`: 접이식 백업/복원 UI, 파일 선검사 및 미리보기, Finding별 적용/건너뛰기, 충돌 확인, 새 검사/결과 삭제 시 미리보기 초기화.
- `frontend/src/app-shell-d5a.css`: 새 영역에 한정한 스타일.
- `frontend/tests/analyst-review-backup.test.ts`, `frontend/browser-tests/analyst-review-backup.spec.ts`: 보안 경계와 브라우저 동작 테스트.

API, CLI, Semgrep, Finding/Evidence 계약, 탐지 로직은 변경하지 않았다.

## 검증

시작 기준은 `63f2626ad1719a6b7a143ed03693206b9c83be6b`이며, `origin/main` 및 GitHub `main`과 일치했다. 해당 SHA의 Run `41278062594`는 `push / completed / success`였고 Python/CLI, Semgrep 1.182.1, React dashboard 필수 job이 성공했다. 구현은 이 SHA에서 분기한 `/tmp/ai-csa-phase8e`의 `phase/8e-analyst-review-backup` 격리 worktree에서 진행했다.

실행 결과:

- `mise exec node@24 -- npm run typecheck` — PASS
- `mise exec node@24 -- npm test` — PASS, 11개 파일 / 106개 테스트
- `mise exec node@24 -- npm run build` — PASS
- `mise exec node@24 -- npx playwright test --config=.tmp-phase8e-playwright.config.ts` — PASS, 24/24 (기존 Playwright 기본 포트에 실행 중인 사용자 서버가 있어 4185 포트를 쓰는 임시 설정으로 격리 실행)
- UI-D3 Finding 목록 위치 회귀 — PASS, 1440px에서 첫 목록 위치 약 781px로 기존 810px 미만 기준 유지
- `SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs` — PASS, 542 passed / 28 skipped. Skip은 기존 명시적 Ollama 실험 opt-in 테스트다.
- `mise exec node@24 -- env SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 npm run test:e2e:real` — PASS, 실제 로컬 FastAPI–Semgrep 브라우저 E2E 1/1
- `git diff --check` — PASS

첫 전체 Playwright 실행에서 백업 도움말 텍스트 16px가 기존 17px 가독성 회귀 기준에 걸렸다. 파일 도움말 및 복원 목록 요약의 글자 크기를 17px로 올린 뒤 production build와 전체 Playwright를 다시 실행해 통과했다. 테스트는 완화하지 않았다. 테스트 중 다른 Phase 스크린샷이 갱신된 것은 이 worktree에서만 기준 커밋 상태로 복원했고, 이번 Phase의 합성 캡처는 유지했다.

Chromium 전체 테스트 및 로컬 실제 Semgrep E2E는 통과했다. 실제 Safari 수동 검수, 200% 브라우저 확대 및 axe 검사는 `NOT_TESTED`다. 자동 검증은 이 검수들을 대체하지 않는다.

화면 자료: [`docs/assets/phase8e/restore-preview-1440.png`](assets/phase8e/restore-preview-1440.png) (합성 프로젝트와 합성 Finding만 사용).

## 알려진 한계

- 완전히 같은 Finding 식별 메타데이터도 원본 코드 내용이 같음을 보장하지 않는다.
- 백업에 메모를 넣으면 사용자가 다운로드한 뒤 파일의 보관과 공유를 관리해야 한다.
- 백업 파일을 브라우저 메모리에서 지워도 이미 디스크에 저장된 파일을 회수하거나 삭제하지 않는다.
- 검증 불가능하거나 일부만 일치하는 파일은 수동 복원도 허용하지 않는다.
- 실제 Safari 검수 여부는 Chromium 자동화와 별도로 기록한다.
