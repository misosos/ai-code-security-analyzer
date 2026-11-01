# Phase 8G — 접근성·브라우저 검증 결과

## 시작 Gate 및 실행 환경

- 검증 기준 SHA: `f046f61a8ac1f60dfa7c3ed0a67a41e392fc8ad7`
- Phase 8F 기능 SHA: `df925597045ce894085ccd626a58acb961a2973d`
- Gate: Phase 8F SHA가 main Merge Commit의 조상이고, 두 트리가 동일함을 확인했다.
- GitHub Actions: Run `41305915426`, `push / completed / success`; Python, React dashboard, Semgrep 1.182.1 필수 작업 성공, artifact 0개.
- 격리 worktree: `/tmp/ai-csa-phase8g`, 브랜치 `phase/8g-accessibility-acceptance`.
- macOS 15.7.7 arm64, Node.js 24.22.2, npm 11.19.1, Python 3.12.7, uv 0.11.26.
- Playwright 1.64.1, Chromium (Playwright bundled), WebKit 27.2 / build 2370, Semgrep 1.182.1.
- axe: `@axe-core/playwright` 4.14.0 및 함께 고정된 `axe-core` 4.14.x.
- 실제 macOS Safari 버전은 확인하지 않았다.

Phase 8F main 병합 SHA와 파일 트리를 독립 검증한 뒤 시작했다. 원래 Desktop 작업 폴더의 변경과 미추적 자료는 이 worktree에서 수정하지 않았다.

## 접근성 자동 검사

Chromium에서 검사 시작, 결과 및 Finding 상세, 검토/백업/복원 미리보기, 비교 범주, 사용 안내, API 오류, 부분 검사, 0건 결과, 잘못된 JSON/메모 오류를 axe로 검사했다. 전체 12개 화면 상태에서 최종 위반은 0건이다. 이는 검사한 화면과 규칙 범위에 대한 자동화 결과이며 WCAG 적합성 인증은 아니다.

초기 검사에서 확인한 실제 문제와 수정:

- `label-content-name-mismatch` (serious): Finding 행의 근거 아이콘에 별도 접근성 이름을 지정해 버튼의 보이는 텍스트와 이름이 달랐다. 아이콘은 장식으로 숨기고, 근거 연결 상태를 일반 보조 텍스트로 전달하도록 정리했다.
- `scrollable-region-focusable` (serious): 사용 안내의 긴 명령 코드 블록이 키보드로 스크롤되지 않았다. 세 `<pre>` 영역에 순차 포커스와 목적을 제공했다.
- 내보내기 컨트롤의 보이는 이름과 ARIA 이름 불일치도 확인해 텍스트와 이름을 맞췄다.

기본 규칙을 비활성화하거나 예외 처리하지 않았다. `@axe-core/playwright`는 개발 의존성으로만 추가했다. `npm audit --omit=optional --audit-level=moderate` 결과 취약점 0건이었다. npm은 `fsevents` 선택 의존성 설치 스크립트가 승인되지 않아 실행하지 않았다는 경고를 보였고, 해당 스크립트를 우회 실행하지 않았다.

## 키보드 및 브라우저 검증

- 키보드 흐름: 검사 폼 이동·입력·실행, 결과 메뉴, Finding 선택, 메모 입력, 검색, Markdown/JSON 다운로드, JSON 복원 미리보기와 항목 적용, 결과 삭제를 합성 데이터로 수행했다.
- 모바일 Drawer: Enter/Space 열기, Tab 이동, Escape 닫기 및 포커스 복귀를 확인했다.
- 네이티브 검토 상태 `<select>`는 포커스 도달을 검증했다. macOS Playwright에서 시스템 선택 팝업의 키 입력으로 값을 확정하지 못해 값 선택 자체는 `selectOption`으로 확인했다. 실제 Safari에서 키보드만으로 옵션을 선택하는 단계는 사용자 검수로 남긴다.
- Chromium 전체 브라우저: 최종 `npm run test:browser` 37/37 통과. 명령은 격리된 preview 포트 `4199`를 사용했다.
- WebKit: 별도 `npm run test:browser:webkit` 2/2 통과. 검사·Finding 검토·Markdown/JSON 내보내기·복원 미리보기와 모바일 Drawer를 확인했다. WebKit은 실제 Safari 앱 검수와 다르다.
- CI: axe 검사 파일은 기존 `npm run test:browser`에 포함되며 GitHub Actions React dashboard 단계에서 실행된다. WebKit은 macOS 로컬 전용 별도 명령으로 두었다.

## 확대·반응형·시각 자료

실제 브라우저 확대 200%는 자동화하지 않았다. CSS viewport 720, 512, 400, 320px를 이용한 재배치 대리 검증을 수행해 가로 넘침과 핵심 컨트롤 표시를 확인했다. 이는 실제 200% 확대 PASS가 아니다.

기존 브라우저 회귀 테스트와 WebKit에서 1920, 1440, 1280, 1024, 768, 600, 390, 320px 폭을 확인했다. 1280px 결과 요약에서 텍스트가 좁은 열에 눌리는 것을 발견해 1300px 이하에서 요약 영역을 두 열 레이아웃의 전체 폭에 배치했다. 1500px 이하의 심각도 요약은 다섯 항목을 좁은 폭에 가로로 겹치지 않도록 세로형 항목으로 재배치했다. 폰트 크기를 줄이지 않았다.

1440×900 UI-D3 회귀 기준:

- Finding 목록 시작 Y: `807.2px` (기준 `< 810px` 통과)
- 첫 Finding 행: 기존 기준 `< 870px` 통과
- 제목: `36.72px`; 본문 `19px`; Sidebar `19px`; 주요 입력/버튼 `18px` 유지
- 비교 보고서와 Finding 상세 화면은 합성 fixture로 캡처했다.

검토한 증거:

- [1440px Finding 검토 화면](assets/phase8g/finding-review-1440.png)
- [1440px JSON 복원 미리보기](assets/phase8g/backup-preview-1440.png)
- [320px CSS viewport 재배치 대리 검증](assets/phase8g/css-viewport-reflow-320.png)
- [WebKit 모바일 Drawer](assets/phase8g/webkit-mobile-drawer-390.png)

검사 후 스크린샷을 직접 확인했다. 테스트가 덮어쓴 기존 Phase 스크린샷은 격리 worktree의 기존 파일만 복구했으며, 위 `phase8g` 증거만 새로 남겼다.

## 테스트 결과

| 검증 | 결과 |
|---|---|
| `uv lock --check` | PASS |
| `uv run --locked semgrep --version` | PASS — 1.182.1 |
| `npm run typecheck` | PASS |
| `npm test` | PASS — 11 파일, 106 테스트 |
| `npm run build` | PASS |
| axe 포함 전체 Chromium Playwright | PASS — 37 테스트 |
| 별도 Playwright WebKit | PASS — 2 테스트 |
| Phase 8F 실제 FastAPI–Semgrep–Chromium E2E | PASS — 2 테스트, 16.364초 |
| Python 전체 `uv run --locked python -m pytest -q -rs` | PASS — 542 통과, 28 선택형 Ollama 테스트 skip, 1 deprecation warning |
| Semgrep 1.182.1 실통합 CI 명령 | PASS — 44 통과, 1 deprecation warning |
| `npm audit --omit=optional --audit-level=moderate` | PASS — 취약점 0건 |
| `git diff --check` | PASS |

주요 실행 명령:

```text
uv lock --check
uv run --locked semgrep --version
uv run --locked python -m pytest -q -rs
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs tests/test_semgrep_integration.py tests/test_scan_e2e.py tests/test_security_baseline.py tests/test_semgrep_taint_evaluation.py tests/test_command_injection_taint.py tests/test_command_injection_hardening.py tests/test_command_injection_phase6f.py tests/test_api_semgrep_e2e.py tests/test_firestore_context_validation.py tests/test_react_html_phase6g.py tests/test_eval_taint_phase6h.py tests/test_taint_trace_phase6i.py
npm run typecheck
npm test
npm run build
CI=1 BROWSER_TEST_PREVIEW_PORT=<격리 포트> npm run test:browser
CI=1 BROWSER_TEST_PREVIEW_PORT=<별도 격리 포트> npm run test:browser:webkit
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 npm run test:e2e:real
npm audit --omit=optional --audit-level=moderate
git diff --check
```

실제 E2E는 별도의 임시 프로젝트와 loopback FastAPI를 사용했다. Finding 기준/추가/유지 결과, 검토 상태와 메모, 보고서 및 백업, 복원, 민감정보 미노출 흐름이 성공했다. 첫 시도에서는 새 접근성 이름 때문에 기존 E2E의 Finding 선택 locator가 맞지 않아 중단되었다. locator를 화면에 보이는 파일 경로와 행 번호 기준으로 맞춘 뒤 실제 E2E 2개가 모두 통과했다. 중단된 첫 실행의 서버는 종료하고 그 실행이 만든 임시 디렉터리를 정리했다.

일반 전체 Chromium 테스트 중 UI-D3 목록 위치가 `866.8px`로 실패한 중간 시도도 있었다. 심각도 요약의 줄바꿈 배치를 다시 조정하고 본문 글자 크기를 복원한 후 최종 수치 `807.2px`로 회귀 검증을 통과했다. 임계값을 낮추지 않았다.

## 보안 및 계약 회귀

FastAPI, CLI, Semgrep 규칙/판정, Finding/Evidence DTO, 분석가 상태의 메모리 전용 정책, JSON 복원 조건, Markdown/JSON 보고서 계약은 변경하지 않았다. 검토 상태와 보안 판정을 분리했다. 토큰, 코드 원문, 절대 경로를 테스트 자료에 기록하지 않았다. 실연동 테스트에서 기존 Phase 8F의 합성 canary/토큰/임시 절대 경로 미노출 검증이 통과했다.

## 사용자 검수 대기

- 실제 macOS Safari와 iOS Safari: `NOT_TESTED`
- 실제 브라우저 200% 확대: `NOT_TESTED` (CSS viewport 대리 검증만 수행)
- VoiceOver: `NOT_TESTED`
- 실제 Safari에서 네이티브 선택창 키보드 조작: `NOT_TESTED`
- 실제 사용자 수용: `SAFARI_USER_ACCEPTANCE_PENDING`

수동 절차는 [Safari·접근성 사용자 검수표](phase8g-manual-safari-accessibility-acceptance.md)를 따른다.
