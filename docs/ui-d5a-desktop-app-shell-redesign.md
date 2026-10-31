# UI-D5A — 데스크톱 앱 셸 재구성

## 시작 상태 및 Gate

- 작업 기준 커밋: `9f87fac04d5ec79cd17d2e9b77027c8920a00bb7`
- 브랜치: `main`
- `origin/main` 및 GitHub `main`: `ecb6cfdc6f069877ee849604d59be3bab0e772f4`
- 로컬 HEAD는 원격보다 2커밋 앞서 있습니다. 현재 HEAD 자체의 GitHub Actions CI는 없습니다. 최신 확인 성공 CI는 Run `41195628362`이며 SHA `ecb6cfd`의 push 실행입니다.
- 작업 전부터 `App.tsx`, CSS, 브라우저 테스트에 변경이 있었고 D1/D4C 관련 문서·자산이 미추적 상태였습니다. 이를 제거하거나 일괄 스테이징하지 않았습니다.

## 요구와 기존 구조

사용자는 기존 사이버펑크 테마와 큰 글씨를 유지하면서 브랜드·탐색·작업 영역이 하나의 데스크톱 앱처럼 정리되길 원했습니다. 직전 구조는 로고만 있는 상단 바가 64px 높이로 전체 너비를 차지하고, 그 아래에 사이드바와 메인 화면이 시작됐습니다. API 상태는 이미 사이드바 하단에 있었지만 브랜드는 헤더에 따로 남아 있었습니다.

참고한 OmniRoute 화면에서는 앱 브랜드, 메뉴, 하단 상태를 한 사이드바로 모으고 오른쪽을 작업 영역으로 쓰는 원칙만 취했습니다. 밝은 테마, 작은 글자, 복잡한 메뉴, 제품 고유 요소나 코드는 가져오지 않았습니다.

## 구현

- 데스크톱의 전체 너비 헤더를 제거하고 셸을 `Sidebar + Main` 그리드로 변경했습니다.
- 기존 육각형 로고를 사이드바 상단에 배치하고 `AI Code Security` 이름을 한 번 표시했습니다. 기존 접근 가능한 링크 이름과 `#main-content` 이동을 보존했습니다.
- 기존 메뉴 3개, 접기 버튼, API 연결/옵션 상태를 유지했습니다.
- 데스크톱 사이드바 폭은 272px, 1000px 이하 태블릿에서는 240px입니다. 접힌 데스크톱 폭은 76px입니다.
- 메인 콘텐츠는 사이드바 오른쪽 x좌표에서 시작하며, 기존 페이지별 콘텐츠와 검사 설정 구조는 변경하지 않았습니다.
- 모바일에는 64px 높이의 로고·메뉴 전용 바를 남겼습니다. Drawer 열기/닫기, Escape, 메뉴 선택 후 포커스 복귀를 유지했습니다.
- `frontend/src/app-shell-d5a.css`를 추가해 셸 변경을 분리했습니다. API 상태 확인, 인증, 검사 및 Finding 계약은 변경하지 않았습니다.

## 브라우저 측정 및 시각 확인

Chromium에서 100% 기본 배율로 확인했습니다.

| 뷰포트 | Sidebar x/y/폭/높이 | Main x | 제목 | 메뉴 | 가로 넘침 |
|---|---:|---:|---:|---:|---:|
| 1920×1080 | 0 / 0 / 272 / 1080 | 272 | 42px | 19px | 0px |
| 1440×900 | 0 / 0 / 272 / 900 | 272 | 36.72px | 19px | 0px |
| 1280×800 | 0 / 0 / 272 / 800 | 272 | 36px | 19px | 0px |
| 1000×800 | 0 / 0 / 240 / 800 | 240 | 36px | 19px | 0px |
| 768×1024 | 0 / 0 / 240 / 1024 | 240 | 36px | 19px | 0px |
| 390×844 | Drawer 닫힘, 상단 바 64px | 0 | 32px | 18px | 0px |
| 320×800 | Drawer 닫힘, 상단 바 64px | 0 | 32px | 18px | 0px |

생성한 Before/After 스크린샷은 같은 1440×900 조건을 사용했습니다. Before는 UI-D4C-H의 로고 전용 상단 바 화면이며, After는 이번 React 구현을 합성 API 데이터로 렌더링한 화면입니다. 검사 결과 화면도 합성 Finding 하나를 사용해 확인했습니다. 스크린샷을 생성한 뒤 실제 이미지 내용을 확인했습니다.

- Before: `docs/assets/ui-d5a/before-logo-only-header-1440x900.png`
- 시작 화면: `docs/assets/ui-d5a/start-1440x900.png`, `start-1920x1080.png`
- 결과 화면: `docs/assets/ui-d5a/finding-results-1440x900.png`, `empty-results-1440x900.png`
- 사용 안내: `docs/assets/ui-d5a/guide-1440x900.png`
- 모바일: `docs/assets/ui-d5a/mobile-start-390x844.png`, `mobile-menu-390x844.png`

데스크톱에서는 헤더가 숨겨진 빈 공간으로 남지 않고 Sidebar가 y=0부터 시작합니다. 모바일에서는 별도의 작은 메뉴 바가 유지됩니다. 실제 Safari 수동 검수는 수행하지 않았습니다.

## 스킬 및 테스트

- `design-taste-frontend`의 `SKILL.md`와 `references/app-screens.md`를 확인하고 App Screen 원칙인 브랜드가 있는 셸, 목적 중심 탐색, 데이터/작업 영역 구분을 적용했습니다. 기존 승인 디자인과 사이버펑크 팔레트가 우선이므로 스타일 재추첨은 하지 않았습니다.
- 설치된 Playwright 스킬 지침과 저장소의 Playwright 설정을 확인하고 기존 Chromium 테스트 환경을 사용했습니다.
- TypeScript: 통과 (`npm run typecheck`)
- Production build: 통과 (`npm run build`)
- Vitest: 4개 파일, 44개 통과 (`npm test`)
- Chromium Playwright: 19개 통과 (`npm run test:browser`)
- 실제 합성 FastAPI–Semgrep E2E: 1개 통과 (`SEMGREP_REQUIRED=1 npm run test:e2e:real`, Semgrep 1.182.1)
- 새 셸 테스트는 1920, 1440, 1280, 1000, 768, 390, 320px 너비의 레이아웃/넘침과 모바일 Escape·메뉴 이동을 확인했습니다.
- 자동 axe 검사는 실행하지 않았고, 실제 Safari 수동 검수도 미실행입니다.

Playwright 회귀 테스트가 기존 추적 `docs/assets` 스크린샷을 재생성했지만, 해당 파일은 작업 전 깨끗했음을 확인한 뒤 원래 Git 상태로 복구했습니다. 새 D5A 스크린샷만 별도 경로에 보관했습니다.

## 남은 제한

- GitHub Actions는 원격 `ecb6cfd`까지만 성공했습니다. 새 로컬 커밋 SHA에는 원격 CI가 없습니다.
- Safari/WebKit 실사용 확인 및 axe 검사는 아직 없습니다.
- 기존 사용자 미커밋 변경이 같은 UI 소스/테스트 파일에 남아 있어, 커밋 시 D5A 변경만 선택적으로 스테이징해야 합니다.
