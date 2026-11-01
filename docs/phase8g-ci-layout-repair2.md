# Phase 8G CI Repair 2 — Linux Chromium Finding 행 위치

## 시작 Gate

- Repository: `misosos/ai-code-security-analyzer`
- 시작 기준: `985f83e5f289fa7a87a52b7a99598f93033a75bb`
- `origin/main` 및 GitHub `main`: 시작 시 기준 SHA와 일치
- GitHub Actions Run `41322817993`: `push / completed / failure`
- Python tests and CLI: SUCCESS
- Semgrep 1.182.1 integration: SUCCESS
- React dashboard: FAILURE
- Chromium browser smoke: 36 passed / 1 failed; 실패로 실제 FastAPI–Semgrep E2E가 skip됨
- 실패 지점: `frontend/browser-tests/ui-d3.spec.ts`의 결과 목록 레이아웃 검증
- 격리 worktree: `/tmp/ai-csa-phase8g-ci-repair2`
- 브랜치: `phase/8g-ci-repair2`
- 원래 Desktop worktree는 작업 전부터 미커밋 및 미추적 변경이 있어 수정하지 않았다.

## 실패 원인

실패 테스트의 두 기준은 기존대로 목록 시작 `<810px`, 첫 Finding 행 `<870px`이다. 기준을 변경하지 않았다.

Linux Chromium 로그의 1440×900 측정값:

| 요소 | 위치/크기 |
|---|---:|
| `.overview-grid` | Y 298px, 높이 185px |
| `.overview-grid` 자식 카드 | 높이 159px |
| `.results-layout` / 목록 시작 | Y 809.875px — 통과 여유 0.125px |
| 첫 `.finding-row` | 약 Y 870px — 실패 |
| `.list-caption` | 높이 60px |

기준 SHA의 macOS Chromium 측정값:

| 요소 | 위치/크기 |
|---|---:|
| `.overview-grid` | Y 296.593px, 높이 157.593px |
| Grid 자식 카드 | 높이 131.593px |
| `.results-layout` / 목록 시작 | Y 781.8125px |
| 첫 `.finding-row` | Y 841.8125px |

CSS에서 `.ui-d2 .overview-grid`는 위아래 각각 12px 패딩을 주고 있었다. macOS와 Linux 모두 Grid 자식 카드가 부모의 콘텐츠 기반 행 높이를 결정했고, 부모에는 이 24px의 외부 여백이 별도로 더해졌다. Linux 로그가 보고한 자식 높이는 macOS보다 27.4px 더 컸다. 글꼴 대체 및 줄바꿈을 포함한 플랫폼별 고유 콘텐츠 높이 차이가 있지만, CI 로그만으로 그 차이를 특정 텍스트 한 곳이나 글꼴 하나로 단정하지 않는다.

목록 캡션 높이가 60px이므로 목록 시작이 경계에 걸리면 첫 Finding 행도 같은 여유만큼 뒤로 밀린다. 따라서 행 자체나 테스트 기준을 조정하지 않고, 카드 내부의 글자와 패딩은 유지한 채 부모의 중복된 세로 패딩만 제거했다.

## 수정

수정 파일: `frontend/src/app-shell-d5a.css`

761~1500px 데스크톱 결과 화면에서 `.overview-grid.analyst-overview`의 `padding-block`을 0으로 재정의했다. 기본 카드 내부 패딩, 텍스트 크기, Grid 자식 콘텐츠, finding 행 간격은 그대로다. 높이 고정, 숨김, 겹침, 음수 margin, transform 및 React 구조 변경은 사용하지 않았다.

이 변경은 부모의 기존 위아래 패딩 12px씩, 총 24px를 제거한다. 기존 1300px 이하의 2열 재배치는 유지되며, 760px 이하 모바일에는 이 미디어 규칙이 적용되지 않는다.

## 수정 전후 측정

### macOS Chromium 실제 측정 — 1440×900

| 요소 | 수정 전 | 수정 후 | 변화 |
|---|---:|---:|---:|
| `.overview-grid` 높이 | 157.593px | 133.593px | -24px |
| 목록 시작 (`.results-layout`) | 781.8125px | 757.8125px | -24px |
| 첫 Finding 행 | 841.8125px | 817.8125px | -24px |
| 목록 기준 여유 (`<810`) | 28.1875px | 52.1875px | +24px |
| 첫 행 기준 여유 (`<870`) | 28.1875px | 52.1875px | +24px |

### Linux Chromium — 로컬 재현 불가

Docker daemon이 실행 중이지 않아 Linux Chromium을 로컬에서 재현하지 못했다. 따라서 수정 후 Linux 결과는 `NOT_VERIFIED`다. CSS 변경은 1440px 화면의 부모 패딩만 정확히 24px 제거하고 콘텐츠 행 크기는 변경하지 않는다. 기존 CI 위치에 이 차이를 적용한 산술상 예상값은 목록 `785.875px`, 첫 행 약 `846px`로 각각 기존 기준에서 24px 여유다. 이는 실제 Linux 재측정 결과가 아니며 PASS 증거로 취급하지 않는다. 최종 Linux 복구 여부는 수정 SHA의 GitHub Actions로 확인해야 한다.

## 검증 환경

- macOS 15.7.7 arm64
- Node.js 24.22.2 / npm 11.19.1
- Python 3.12.7 / uv 0.11.26
- Playwright 1.64.1
- Chromium 156.0.8078.4
- WebKit 27.2
- Semgrep 1.182.1
- `@axe-core/playwright` 4.14.0

## 회귀 검증 결과

| 검증 | 결과 |
|---|---|
| `npm run typecheck` | PASS |
| `npm test` | PASS — 11개 파일, 106개 테스트 |
| `npm run build` | PASS |
| `CI=1 BROWSER_TEST_PREVIEW_PORT=4222 npm run test:browser` | PASS — 37/37, 45.1초; axe 및 UI-D3 포함 |
| UI-D3 1440×900 집중 측정 | PASS — 목록 757.8125px, 첫 행 817.8125px; 기준 `<810` / `<870` 유지 |
| `CI=1 BROWSER_TEST_PREVIEW_PORT=4223 npm run test:browser:webkit` | PASS — 2/2 |
| axe 접근성 시나리오 | PASS — 7개 axe 테스트가 전체 Chromium 37개에 포함 |
| 반응형 및 오버플로 | PASS — 기존 테스트에서 1920/1440/1280/1024/768/600/390/320px 검사 |
| `uv lock --check && uv run --locked python -m pytest -q -rs` | PASS — 542 passed, 28 skipped, 경고 1건, 316.18초 |
| `semgrep --version` | PASS — 1.182.1 |
| CI Semgrep 실통합 테스트 명령 (12개 지정 테스트 모듈) | PASS — 44 passed, 경고 1건, 272.32초 |
| FastAPI–Semgrep–Chromium E2E | PASS — 2/2, 39.003초; 기존 합성 E2E를 재사용 |
| `git diff --check` 및 커밋 diff 검사 | PASS — stage 전, stage 후, 커밋 diff 모두 확인 |

Python의 28개 skip은 저장소에서 명시적으로 opt-in인 합성 Ollama 테스트다. 두 Python 실행의 경고는 Starlette/AnyIO `BlockingPortal` deprecation이다. 실제 macOS Safari 검수는 수행하지 않았으며 WebKit 결과를 Safari PASS로 대체하지 않는다.

브라우저 회귀 테스트는 기존 Phase 문서용 스크린샷을 다시 생성했지만, 격리 worktree 시작 시 해당 파일들이 깨끗한 tracked 상태였으므로 테스트 후 모두 시작 커밋 기준으로 복원했다. 해당 이미지는 이번 변경에 포함하지 않는다.

## 기능 및 보안 영향

변경은 scoped CSS 한 줄에 한정된다. App, API, 인증/토큰 처리, Semgrep, Finding/Evidence, 분석가 검토, 비교 및 백업 계약은 변경하지 않았다. 실제 E2E는 기존 합성 프로젝트로 다시 실행해 통과했다. 새 네트워크 엔드포인트나 의존성은 추가하지 않았다.

## 남은 검증

- 수정 후 Linux Chromium 좌표: `NOT_VERIFIED`; 새 SHA를 Push한 뒤 GitHub Actions에서 확인 필요
- 실제 macOS Safari 사용자 수용: `SAFARI_USER_ACCEPTANCE_PENDING`
- axe 자동 테스트 통과는 WCAG 전체 준수 증명이 아니다.
