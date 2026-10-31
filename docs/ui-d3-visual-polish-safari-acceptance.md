# Phase UI-D3 — Safari 시각 다듬기 및 사용성 검증

## 범위와 기준

- 프로젝트: `misosos/ai-code-security-analyzer`
- 기준 UI 커밋: `c10c46ed8acab12a7e72cf61d67385e3c1746875`
- 승인 디자인: Option B 기반, 결과 검토에는 Option C 흐름, Option A 장식은 기존처럼 절제
- 사용자 관찰: Safari에서 `Command + 0`으로 확대를 초기화한 뒤 글자와 컨트롤이 더 읽기 쉬워졌음. 확대 비율이 유일한 원인이라고 단정하지 않는다.
- 작업 범위: UI 레이아웃 보정, 브라우저 테스트, 증거 문서와 합성 스크린샷. API 및 분석 계약은 변경하지 않았다.

## 시작 Gate

| 항목 | 결과 |
|---|---|
| 로컬 HEAD | `c10c46ed8acab12a7e72cf61d67385e3c1746875` |
| 브랜치 | `main` |
| `origin/main` | `de83be32775b8503c1e907d47ddf79c89e0b05e3` |
| GitHub `main` | `de83be32775b8503c1e907d47ddf79c89e0b05e3` |
| ahead / behind | 로컬 6개 앞, 0개 뒤 |
| 기준 HEAD의 Actions | 조회 결과 없음 — `NOT_VERIFIED` |
| 작업 시작 시 트리 | 기존 파일 수정 및 미추적 UI-D1/UI-D1-Y 자료가 이미 존재함. 보존 대상으로 두고 이 Phase 변경과 분리했다. |

기존 수정 파일 `frontend/browser-tests/dashboard.spec.ts`, `frontend/src/readability.css` 및 미추적 자료는 이 Phase에서 고치거나 스테이징하지 않았다. Git push를 하지 않았다.

## 디자인·브라우저 스킬

- `design-taste-frontend`: `SKILL.md`와 `references/app-screens.md`를 확인했다. 실제 작업용 앱 화면의 위계와 조작 우선 원칙을 적용하되, 사용자가 이미 승인한 Option B와 큰 글씨 요구를 우선했다. 새 방향 추첨이나 새 시안 제작은 하지 않았다.
- `playwright`: 스킬 절차를 확인했고 기존 저장소의 Playwright 테스트 구성을 사용해 실제 Chromium에서 조작·렌더링·측정을 수행했다.
- Figma MCP는 사용하지 않았다.

## UI-D2에서 확인한 부분과 수정

기존 1440×900 화면에서는 검사 설정 패널이 약 437px 높이였다. 큰 선택창과 토큰 보안 설명이 필요한 높이였지만, 제목 여백과 컨트롤 사이의 세로 간격에 일부 조정 여지가 있었다. 실행 버튼도 두 번째 열에 있어 토큰 입력 그룹의 아래쪽과 정렬되지 않았다.

`frontend/src/ui-d2.css`의 UI-D3 후속 규칙에서 다음만 조정했다.

- 설정 패널 아래쪽 패딩을 24px에서 18px로 조정
- 설정 제목 아래 간격을 16px에서 12px로 조정
- 데스크톱 컨트롤 행 사이 간격을 18px에서 14px로 조정
- 각 입력 그룹 아래 여백을 줄임
- 실행 버튼을 토큰 그룹 하단에 정렬하고 세로 간격을 4px로 맞춤
- 모바일에서는 실행 버튼이 기존처럼 전체 너비를 유지하도록 정렬을 되돌림
- 결과 제목과 필터를 같은 위쪽 기준선에 정렬
- 중복 라벨을 감추고, 표시 제한 설명은 “현재 응답 최대 50건”으로 짧게 표현
- 결과 화면의 섹션 간격을 12px에서 8px로, 제목과 목록 사이 여백을 20px에서 12px로 조정

선택창 60px, 토큰 입력 60px, 실행 버튼 56px 및 큰 타이포그래피는 줄이지 않았다. 결과 화면의 기존 정보 구조나 Finding/Evidence 렌더링은 변경하지 않았다.

## Chromium 측정 결과

Playwright Chromium 기본 페이지 배율(테스트 컨텍스트 기본값)에서 측정했다. 이 결과는 실제 Safari의 확대 설정이나 렌더링을 증명하지 않는다.

### 검사 시작 — 1440×900

| 요소 | 글자 크기 | 줄 높이 | 높이 |
|---|---:|---:|---:|
| 페이지 제목 | 36.72px | 44.064px | 44px |
| 본문 기준 | 20px | 33px | — |
| 사이드바 메뉴 | 19px | 27.55px | 56px |
| 프로젝트 선택 | 18px | 27px | 60px |
| 규칙 선택 | 18px | 27px | 60px |
| 실행 버튼 | 18px | 27.9px | 56px |

- 검사 설정 패널: 411px (이전 UI-D2 캡처: 약 437px, 약 26px 감소)
- 토큰 그룹: y=444px, h=188px
- 실행 버튼: y=572px, h=56px
- 토큰 그룹과 버튼 하단 정렬 차이: 4px
- 입력과 버튼 크기를 줄이지 않고 설정 패널 내부 여백을 조정했다.

### 검사 결과 — 1440×900

| 요소 | 글자 크기 | 줄 높이 |
|---|---:|---:|
| 페이지 제목 | 36.72px | 44.064px |
| 검사 상태 제목 | 24px | 33.6px |
| 주요 결과 수치 | 40px | 48px |
| Finding 제목 | 19px | 28.5px |
| 상세 제목 | 24px | 31.2px |
| 검색 입력 | 18px | 27.9px |

스크린샷의 Finding과 경로는 브라우저 테스트 전용 합성 fixture이며 실제 프로젝트 결과가 아니다. 토큰은 테스트 메모리에서만 입력했고 캡처에는 포함하지 않았다.

- 제목과 필터는 같은 y=692px 기준선에 정렬됐다.
- Finding Workspace는 y=798px, 첫 Finding 행은 약 y=858px에서 시작한다. UI-D2 측정에서 Workspace는 y=884px부터 시작했다.
- 900px 화면에서 첫 행이 이전보다 더 드러나며, 전체 Finding 검토에는 페이지 스크롤이 필요하다.

## 화면 및 기능 검증

필수 검증 결과:

- TypeScript typecheck: 통과
- Vitest: 44개 통과
- Production build: 통과
- 전체 Chromium Playwright: 15개 통과 (UI-D3 전용 4개 포함)
- 합성 FastAPI–Semgrep E2E: 1개 통과 (`SEMGREP_REQUIRED=1`)
- `git diff --check`: 통과

UI-D3 Playwright 테스트 4개에서 다음을 추가 확인했다.

- 시작 패널의 실제 bounding box, 입력 높이, 글자 크기와 실행 버튼 정렬
- 검사 결과의 상태·요약·Finding 상세, 결과 내보내기와 결과 초기화
- 결과 제목/필터 정렬과 첫 Finding 행의 실제 위치
- 정상 완료 0건, 부분 검사, API 연결 오류의 구분
- 1920×1080, 1440×900, 1280×800, 768×1024, 390×844에서 시작/결과 화면의 가로 넘침 확인
- 모바일 메뉴 열기, Escape 닫기 및 포커스 복귀

검사 결과 화면은 기존 세션 요약 → 상태/제한 → 요약 수치 → Finding 검색·필터 → 목록/상세 순서를 유지한다. 정상 완료와 0건은 안전성 보증이 아니라는 문구가 화면에 보인다. 부분 완료 화면은 검사되지 않은 범위가 있다는 경고를 표시한다.

## 스크린샷

스크린샷은 모두 합성 브라우저 응답으로 생성했고 실제 화면을 열어 확인했다.

- [검사 시작 1440×900](assets/ui-d3/start-1440x900.png)
- [검사 시작 1920×1080](assets/ui-d3/start-1920x1080.png)
- [검사 결과 1440×900](assets/ui-d3/results-1440x900.png)
- [Finding 상세 패널](assets/ui-d3/finding-detail-1440x900.png)
- [부분 검사](assets/ui-d3/partial-results-1440x900.png)
- [정상 완료·발견 항목 0건](assets/ui-d3/zero-findings-1440x900.png)
- [API 연결 오류](assets/ui-d3/api-error-1440x900.png)
- [모바일 검사 시작 390×844](assets/ui-d3/mobile-start-390x844.png)
- [모바일 검사 결과 390×844](assets/ui-d3/mobile-results-390x844.png)
- [모바일 메뉴](assets/ui-d3/mobile-menu-390x844.png)

Before는 [UI-D2 검사 시작](assets/ui-d2/start-1440x900.png)을 사용했다. UI-D2 스크린샷과 UI-D3 스크린샷은 서로 다른 Playwright 실행에서 생성됐으며 동일 fixture의 배치는 같지만 수신 시각은 다를 수 있다.

## 브라우저·접근성 구분

| 검증 | 결과 |
|---|---|
| Chromium | 지정된 5개 viewport에서 검사 시작/결과 레이아웃 및 가로 넘침 확인 |
| WebKit 자동화 | `NOT_TESTED` — 설치된 Playwright 브라우저 목록에 WebKit 없음. 다운로드하지 않음 |
| 실제 Safari 시각 검수 | 사용자 제보상 `Command + 0` 이후 글자와 컨트롤이 좋아졌음. Codex가 Safari를 직접 조작·캡처하지 않았으므로 독립 검수는 `NOT_TESTED` |
| Safari 확대 125/150/200% | `NOT_TESTED` — 실제 확대 기능을 조작하지 않음 |
| axe 자동 검사 | `NOT_TESTED` — 기존 의존성에 axe가 없음. 의존성을 추가하지 않음 |
| 키보드 | 모바일 탐색 Escape 닫기·포커스 복귀 확인. 전체 browser suite의 입력/내비게이션 회귀 통과 |
| 대비 | 이번 Phase에서 자동 대비 계산은 수행하지 않았다. 실제 시각 검토만 수행했으며 WCAG 적합성을 인증하지 않는다. |

## 남은 검증 및 사용자 수용

- 실제 Safari에서 `Command + 0` 상태로 검사 시작, Finding 상세, 모바일 크기 화면을 사용자가 다시 확인해야 한다.
- 실제 API 오류와 결과는 자동화 캡처의 합성 응답과 별도로 현지 환경에서 확인해야 한다.
- 이번 변경은 레이아웃 여백과 버튼 정렬에 한정된다. 결과 정보 구조에는 새로운 UI 변경을 하지 않았다.
- 실제 사용자의 최종 수용은 아직 받지 않았다.
- 전체 Browser suite에서 검색·필터, Finding 선택, 결과 내보내기·초기화, 토큰 처리, API 오류, Sidebar와 모바일 Drawer 회귀도 통과했다.

**판정: 기술 검증 완료 후 사용자 재검토 대기. 실제 Safari 검수 및 사용자 수용 완료를 주장하지 않는다.**
