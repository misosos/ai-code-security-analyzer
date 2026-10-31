# Phase UI-D4C-R — 사용 안내 화면 개선

## 시작 Gate

- 브랜치: `main`
- 작업 시작 HEAD / `origin/main` / GitHub `main`: `ecb6cfdc6f069877ee849604d59be3bab0e772f4` (일치)
- 정확한 SHA의 CI: Run `41195628362`, `push / completed / success`; Python, Semgrep 통합, React/Chromium 필수 작업 성공
- 작업 시작 시 ahead/behind: `0 / 0`
- 기존 로컬 수정과 미추적 파일은 삭제·초기화하지 않았다. 이 Phase에서는 `App.tsx`에 사용 안내 섹션을 추가했으며, 같은 파일의 기존 토큰 보안 수정은 별도 변경으로 보존했다.

## 기존 문제와 변경한 정보 구조

기존 화면은 사용 방법과 긴 용어집을 좌우 카드로 나눴고, 일반 사용자 안내와 서버 운영 명령을 한 화면에 함께 노출했다. 영역별 정보량이 달라 읽는 순서가 끊기고 카드 테두리가 내용보다 먼저 보였다.

사용 안내를 본문 폭 1,000px의 단일 세로 흐름으로 바꿨다.

1. **검사 방법** — 프로젝트 선택, 검사 실행, 결과 검토의 세 단계
2. **검사 결과 이해하기** — 검토 후보의 의미, 추가 확인 필요성, 0건의 한계
3. **추가 안내** — 서버 관리자 설정과 보안 용어 설명을 각각 기본 접힘으로 제공

세 단계는 데스크톱에서 가로로, 900px 이하에서 세로로 표시한다. 각 단계는 반복 카드 대신 상단 구분선과 여백으로 나눈다. 용어집은 여러 카드 대신 정의 목록 한 개를 사용한다.

## 유지한 정보와 기능

- 서버 관리자 안내의 의존성 설치, 빌드·실행, 프로젝트 등록, 토큰 발급, 허용 Origin, 단일 프로젝트 설정 호환성, Vite 개발 실행 명령을 유지했다. 안내는 네이티브 `details/summary`로 접었다.
- Finding, Severity, Unverified, Validated Evidence, Rule Profile, Taint, Source, Sink, Trace, Sanitizer 정의를 유지했다. `Validated Evidence`가 취약점 확정을 뜻하지 않으며 Source/Sink 선언, Trace 부재, Sanitizer 명칭만으로 실제 데이터 흐름·안전성을 확정할 수 없다는 설명도 남겼다.
- 탐지 후보는 취약점 확정이 아니며, 실제 영향은 근거를 확인해야 하고, 0건은 안전성 보장이 아니라는 설명을 기본 화면에 표시한다.
- 결과가 현재 브라우저 세션에서만 보이며 새로고침 또는 창 종료 후 복원되지 않는 제한을 유지했다.
- 검사 시작·결과의 JSX와 API, 인증, Finding/Evidence 계약은 이 Phase에서 변경하지 않았다. 사용 안내에만 적용되는 `.guide-document` 스타일을 추가했다.
- 제품 기능 삭제 후보는 발견하지 않았다. 관리자 안내와 전문 용어의 기본 노출만 접었다.

## 디자인 스킬과 검증 환경

- `design-taste-frontend`의 `SKILL.md`와 `references/app-screens.md`, Playwright 스킬의 브라우저 워크플로를 읽고 앱 화면의 정보 위계, 점진적 공개, 읽기 폭, 시각 확인 절차를 적용했다.
- Chromium 기반 Playwright를 사용했다. 현재 실행 환경에서 WebKit 및 실제 Safari를 사용할 수 없었다. 이번 요청에 언급된 Safari 스크린샷 3장은 대화에 실제 이미지 파일로 제공되지 않아, 작업 전 캡처는 **Chromium의 합성 API 상태**로 직접 생성했다. 따라서 실제 Safari 수용 검수로 간주하지 않는다.
- 서버 응답은 UI 검수용 합성 프로젝트/규칙 데이터이며, 검사 결과를 가짜로 만들지 않았다. 이 화면에서는 실제 토큰을 입력하지 않았다.

## 실제 렌더링 측정

Chromium computed style 및 DOM bounding box 결과:

| Viewport | 안내 폭 | 본문 글자 / 줄 간격 | 접기 제목 | 가로 넘침 |
|---|---:|---:|---:|---:|
| 1440×900 | 1000px | 18px / 30.6px | 19px | 없음 |
| 1920×1080 | 1000px | 18px / 30.6px | 19px | 없음 |
| 390×844 | 354px | 18px | 19px, 높이 64px | 없음 |

1280×800 및 768×1024를 포함한 다섯 지정 viewport의 사용 안내 가로 넘침은 기존 Chromium 회귀 테스트에서 확인했다. 테스트는 화면 너비에 맞춰 본문 폭이 줄어들고 모바일에서 단계가 세로로 놓이는지 확인한다.

## Before / After 자료

모든 자료는 같은 로컬 Chromium 브라우저에서 만들었다. `before`도 작업 전 저장된 앱 화면 캡처이며 실제 Safari 캡처가 아니다.

- Before: `docs/assets/ui-d4c-r/before/guide-1440x900.png`, `guide-1920x1080.png`, `guide-390x844.png`
- After: `docs/assets/ui-d4c-r/after/guide-1440x900.png`, `guide-1920x1080.png`, `guide-390x844.png`
- 상세 펼침: `guide-admin-expanded-1440x900.png`, `guide-glossary-expanded-1440x900.png`
- 측정 자료: `docs/assets/ui-d4c-r/after/layout-measurements.json`

스크린샷을 직접 확인했다. 좌우의 긴 카드 두 개가 없어지고 단계 안내, 결과 해석, 접힌 추가 안내 순서로 읽힌다. 변경 범위는 사용 안내에 한정되어 검사 시작 및 결과 화면은 기존 브라우저 회귀 테스트로 확인했다.

## 테스트 결과와 한계

- TypeScript: `npm run typecheck` 통과
- Production build: `npm run build` 통과
- Vitest: 4개 파일, 44개 테스트 통과
- Chromium Playwright: 전체 17개 테스트 통과. 안내 레이아웃, 접기/펼치기, 키보드 Enter/Space, 모바일, 검사 시작·결과 회귀 포함
- 합성 로컬 FastAPI–Semgrep E2E: `SEMGREP_REQUIRED=1 npm run test:e2e:real` 통과 (1개)
- 키보드 및 지정 viewport 가로 넘침: 통과
- axe 자동 검사: NOT_TESTED (기존 axe 도구가 없음)
- WebKit 및 실제 Safari 수동 검수: NOT_TESTED
- `git diff --check` 및 `git diff --cached --check`: 통과

실제 Safari에서 글꼴 렌더링과 사용 편의성은 사용자가 확인해야 한다. 이 Phase의 결과는 브라우저 검수 준비이지 사용자 최종 승인 선언이 아니다.
