# Phase 8G CI Repair — Finding 목록 레이아웃

## 시작 Gate

- 실패 대상 커밋: `01f115a3ee57f33d81f14735f1dcd52864f68fa6`
- 실패 Run: `41317817332` — `push / completed / failure`
- 실패 작업: React dashboard → Run browser smoke test
- 원격 `main`은 작업 시작 시 실패 SHA와 일치했다.
- 실패 테스트는 `frontend/browser-tests/ui-d3.spec.ts`의 UI-D3 결과 검토 시나리오였다. 브라우저 smoke에서 36개 통과, 1개 실패였고 선행 실패 때문에 Real E2E는 skip됐다. TypeScript/Vitest/build, Python 및 Semgrep job은 성공했다.
- 격리 worktree: `/tmp/ai-csa-phase8g-ci-repair`
- 브랜치: `phase/8g-ci-repair`
- 원래 Desktop worktree의 HEAD와 미커밋·미추적 파일은 변경하지 않았다.

## 원인 진단

1440×900 Linux Chromium에서는 5열 `.overview-grid.analyst-overview`가 플랫폼별 글꼴 메트릭과 줄바꿈에 따라 콘텐츠 기반 높이로 확장됐다. GitHub 측정에서 개요 영역은 Y=298px, 높이=185px였고, 행 안의 카드 높이는 159px였다. 반면 macOS Chromium은 개요 Y=297px, 높이=175px였다. 이 약 10.7px 차이가 이미 여유가 거의 없던 뒤쪽 콘텐츠 흐름에 더해져 목록이 Y=817.875px에 놓였다.

CI 로그의 추가 측정은 심각도 칩 영역 56px, 결과 제목/필터 영역 82px였다. 제목 및 필터 영역이 아니라 개요 Grid의 콘텐츠 기반 행 높이가 주된 차이였다. macOS에서 각 개요 카드에 `align-self:start`를 임시 적용해 자연 높이를 분리 측정했을 때 심각도 카드가 148.97px로 가장 높았고, 나머지 카드의 자연 높이는 116~127.6px였다. 따라서 고정 높이를 강제하지 않고 심각도 카드의 불필요한 세로 간격을 줄여 그리드 행과 뒤쪽 콘텐츠의 여유를 확보했다.

Linux에서 사용된 폰트별 실제 줄바꿈을 직접 재측정하지 못했으므로, 특정 글꼴 하나를 단독 원인으로 확정하지 않는다. 확인된 근본 구조는 좁은 5열 요약에서 카드 내부 텍스트의 intrinsic sizing이 그리드 높이를 결정하고, CI의 글꼴 폭 차이가 그 높이를 키운다는 점이다.

## 변경 내용

`frontend/src/app-shell-d5a.css`의 761~1500px 데스크톱 구간만 조정했다.

- 개요 영역 아래 여백: 16px → 8px
- 심각도 카드의 세로 패딩: 기존 8px → 4px
- 심각도 칩의 위·아래 여백: 6px/4px → 0px
- 짧은 보조 설명의 위 여백 제거, 줄높이 1.5 → 1.3
- 세 개 요약 카드 설명은 한국어 단어 경계에서 줄바꿈하도록 설정

모든 문구와 카드 내용을 유지했다. 글꼴 크기, 기존 `<810px`/`<870px` 테스트 기준, CSS 구조 및 모바일 스타일은 변경하지 않았다. 높이를 고정하거나 내용을 숨기지 않았고 음수 여백, transform, React 구조 변경도 사용하지 않았다.

## 전후 측정

| 환경 | 개요 영역 | Finding 목록 시작 | 첫 Finding 행 |
|---|---:|---:|---:|
| 기존 CI Linux Chromium | Y 298 / 높이 185px | 817.875px — 실패 | 약 877.875px — 실패 |
| 기존 macOS Chromium | Y 297 / 높이 175px | 807.2px — 통과 | `<870px` 기준 통과 (정확 좌표 미기록) |
| 수정 후 macOS Chromium | Y 297 / 높이 158px | 781.8125px — 통과 | 841.8125px — 통과 |

수정 후 macOS 결과는 `<810px` 목록 기준에 약 28.2px 여유를 확보했다. 첫 행도 `<870px` 기준을 통과했다. 개요 카드의 텍스트 크기는 20px로 유지했고, 페이지 제목 36.72px, 본문 19px, Sidebar 19px, 주요 컨트롤 18px도 회귀 테스트에서 확인했다.

## 검증 환경과 결과

- macOS 15.7.7 arm64
- Node.js 24.22.2 / npm 11.19.1
- Python 3.12.7 / uv 0.11.26
- Playwright 1.64.1
- Chromium 156.0.8078.4
- WebKit 27.2
- Semgrep 1.182.1

| 검증 | 실행 결과 |
|---|---|
| `npm run typecheck` | PASS |
| `npm test` | PASS — 11개 파일, 106개 테스트 |
| `npm run build` | PASS |
| UI-D3 집중 테스트 (`ui-d3.spec.ts`) | PASS — 4/4; 목록 781.8125px, 첫 행 841.8125px |
| 전체 Chromium `CI=1 BROWSER_TEST_PREVIEW_PORT=4220 npm run test:browser` | PASS — 37/37; axe 검사 포함 |
| WebKit `CI=1 BROWSER_TEST_PREVIEW_PORT=4221 npm run test:browser:webkit` | PASS — 2/2 |
| `uv lock --check` | PASS |
| Python 전체 `uv run --locked python -m pytest -q -rs` | PASS — 542 통과, 선택형 28개 skip, Starlette/AnyIO deprecation 경고 1개 |
| Semgrep 1.182.1 CI 통합 pytest 명령 | PASS — 44개 통과, deprecation 경고 1개 |
| `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24.22.2 -- npm run test:e2e:real` (frontend) | PASS — 실제 FastAPI–Semgrep–Chromium 2/2, 24.2초 |
| `git diff --check` | PASS |

기존 브라우저 테스트에서 1920, 1440, 1280, 1024, 768, 600, 390, 320px 폭의 관련 화면을 확인했다. 결과 화면 및 반응형 테스트의 가로 넘침 검사가 통과했고, 1280px 분석가 요약 가독성, 320px 모바일 메뉴/컨트롤, axe 및 키보드 시나리오도 통과했다. 기존 스크린샷 산출물은 테스트가 덮어썼던 파일만 격리 worktree의 기준 버전으로 복구했다.

## 보안 및 기능 회귀

이번 수정은 CSS와 검수 문서에 한정했다. API, Semgrep 판정, Finding/Evidence, 분석가 상태 및 백업/복원 계약은 수정하지 않았다. 실제 합성 FastAPI–Semgrep E2E가 통과했다. 기존 브라우저 테스트에서 토큰·코드 원문·절대 경로 노출 금지, 검토 상태와 보안 판정의 분리, JSON의 자동 적용 금지도 계속 검증했다.

## 제한 사항

- Docker CLI는 있으나 로컬 Docker daemon이 실행되지 않아 Linux Chromium 환경을 재현하지 못했다. 수정 후 Linux 수치는 `NOT_VERIFIED`이며, macOS 결과를 Linux PASS로 간주하지 않는다.
- 다음 Push 후 수정 커밋의 정확한 SHA로 GitHub Actions를 확인해야 Linux CI 복구를 확정할 수 있다.
- 실제 macOS Safari 사용자 검수는 수행하지 않았다. Playwright WebKit 통과는 실제 Safari 검수가 아니며 Safari 사용자 수용은 `SAFARI_USER_ACCEPTANCE_PENDING`이다.
