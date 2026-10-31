# Phase UI-D2 — 승인된 하이브리드 디자인 구현

## 범위와 시작 상태

- 저장소: `misosos/ai-code-security-analyzer`
- 작업 ID: `UI-D2`
- 작업 시작 HEAD: `37229700bb16734a70b2adb6849a668f4075f14d` (`main`)
- 작업 시작 `origin/main` 및 GitHub `main`: `de83be32775b8503c1e907d47ddf79c89e0b05e3`
- 작업 시작 HEAD는 원격보다 5개 커밋 앞서 있었고, HEAD SHA를 대상으로 한 Actions 결과는 없었다. 기존 Run 41048835761은 현재 HEAD의 성공으로 간주하지 않는다.
- 시작 시 이전 UI 작업의 수정·미추적 파일이 있었다. 강제 reset/clean을 하지 않았고 해당 파일은 보존했다.
- Git push는 하지 않았다.

## 승인 디자인 적용

기본은 UI-D1 Option B의 Premium Security Workspace다. 시작 화면은 큰 제목, 라벨형 사이드바, 2열 프로젝트/규칙 선택, 토큰과 실행 액션, 아래의 간결한 검사 흐름을 사용한다. UI-D1 Option C에서는 결과 화면의 세션 맥락 → 후보 목록 → 선택 항목 근거 검토 순서를 적용했다. Option A에서는 메인 작업 영역의 가는 시안/바이올렛 강조와 선택 행의 미세한 발광만 가져왔다.

시안 자체가 합성 데이터를 쓴다는 점을 유지했다. 실제 React 스크린샷은 브라우저 테스트가 주입한 `Synthetic Review Project`, `Baseline Rules` 및 합성 Finding만 표시한다. 이는 UI 렌더링 검증용이며 실제 검사 결과나 API 연결 상태로 제시하지 않는다.

### 디자인 도구 및 참고 자료

- 설치된 `design-taste-frontend`의 `SKILL.md`와 `references/app-screens.md`를 읽고 앱 화면 워크플로를 사용했다. `draw.mjs --app --kind devtools ... --options 3`으로 방향을 조사했으며, 생성된 `data-terminal`은 정보 구조 참고에 그쳤다. 사용자가 승인한 Option B가 우선이므로 자동 생성 방향으로 시안을 대체하지 않았다.
- 설치된 `playwright` 스킬의 CLI 사용법을 확인하고 CLI로 로컬 화면 열기를 시도했다. CLI는 시스템 Google Chrome 경로가 없어 실행되지 않았다. 대신 저장소의 Playwright 1.64.1이 제공하는 로컬 Chromium으로 실제 화면·상호작용·스크린샷 검증을 수행했다.
- UI-D1의 [비교 문서](design-exploration/ui-d1/design-comparison.md), [Option B 시작](design-exploration/ui-d1/screenshots/option-b-start-1440x900.png), [Option B 결과](design-exploration/ui-d1/screenshots/option-b-results-1440x900.png), [Option C 결과](design-exploration/ui-d1/screenshots/option-c-results-1440x900.png), [Option A 시작](design-exploration/ui-d1/screenshots/option-a-start-1440x900.png)을 구현 기준으로 다시 확인했다.
- Figma MCP가 연결되어 있지 않아 사용하지 않았다. 새 UI 라이브러리나 런타임 의존성은 추가하지 않았다. 기존 문서에서 확인한 shadcn/ui(MIT), Origin UI(MIT), Nocturne(Apache-2.0), DefectDojo(BSD-3-Clause), Magic UI의 패턴을 참고만 했으며 외부 소스 코드를 복사하지 않았다.

## 구현 내용

- `frontend/src/ui-d2.css`를 추가하고 `main.tsx`에서 불러와 UI-D2 전용 토큰과 스타일을 적용했다. 다크 네이비 표면, 밝은 한국어 텍스트, 시안/마젠타/바이올렛 강조, 절제된 패널 경계, 명확한 focus ring을 사용한다.
- 검사 설정은 2×2 흐름으로 배치했다. 데스크톱에서 프로젝트/규칙 선택이 위쪽에, 토큰/실행이 아래쪽에 놓인다. 토큰은 기존 `password` 입력, 메모리 내 상태와 요청 헤더 전송 방식을 유지한다. 네이티브 `select`를 유지해 키보드 선택 동작을 보존했다.
- 시작 화면에서 중복된 빠른 시작 아코디언을 제거하고 단계 안내를 한 줄 흐름으로 정리했다. 자세한 설치·운영 설명은 기존 `사용 안내` 화면에서 제공한다.
- 결과는 세션 요약, 검사 상태 및 제한, 통계, Finding 탐색 영역 순으로 배치했다. Finding 목록과 상세를 좌우로 두되 태블릿/모바일에서는 한 열로 바뀐다. 기존 API가 제공하는 제목, 심각도, 경로, 줄, 검증 상태 및 Evidence만 사용한다.
- 모바일 사이드바는 접근 가능한 Drawer로 동작한다. 닫기 전환이 끝난 뒤에 캡처하도록 브라우저 테스트를 보완했고, Escape 종료와 버튼 포커스 복귀를 확인했다.
- 토큰 도움말 행이 입력과 겹치던 고정 그리드 행 높이를 내용 기반으로 바꿨다.

### 실제 브라우저에서 측정한 글자 크기 (1440×900)

| 요소 | computed font-size | line-height | 높이/비고 |
|---|---:|---:|---|
| 페이지 제목 | 36.72px | 44.064px | 주요 제목 |
| 페이지 설명 | 19px | 32.3px | 한국어 본문 |
| 사이드바 메뉴 | 19px | 27.55px | 메뉴 행 높이 56px |
| 컨트롤 레이블 | 18px | 27px | 입력 필드 레이블 |
| 프로젝트 선택 | 18px | 27px | 컨트롤 높이 60px |
| 주요 버튼 | 18px | 27.9px | 실행 버튼 높이 56px |
| 검사 흐름 설명 | 19px | 32.3px | 보안 한계 포함 |
| Finding 제목 | 19px | — | 결과 행 제목 |
| Finding 경로 / 상세 설명 | 18px 이상 | — | 상세 패널에서 확인 |
| 결과 필터/검색 | 18px | — | 선택 입력 높이 52px |

검사 시작 화면의 bounding box: 제목 `top=108, height=100`; 설정 데크 `top=240, height=437`; 폼 `top=309, height=343`; 토큰 그룹 `top=458, height=194`; 검사 흐름 `top=705, height=186`. 토큰 도움말은 입력 밑으로 분리되어 겹치지 않는다.

결과 화면에서 1440×900의 Finding 탐색 헤더는 `top=712`, 목록/상세는 `top=884`였다. 따라서 첫 화면에는 세션·상태·요약·필터가 보이고 목록 시작은 화면 아래쪽에서 이어진다. 작은 글자로 내용을 압축하지 않고 세로 스크롤을 허용한다. 데스크톱 두 패널은 같은 높이를 강제하지 않고 각 콘텐츠에 맞춰 확장된다.

## 검증

| 검사 | 결과 | 근거 |
|---|---|---|
| TypeScript typecheck | PASS | `npm run typecheck` |
| Production build | PASS | `npm run build` |
| Vitest | PASS | 4개 파일, 44개 테스트 |
| Chromium Playwright | PASS | 11개 브라우저 테스트; 시작/결과/검색/선택/내보내기/초기화/오류/부분 상태/모바일 내비게이션 및 화면 크기 포함 |
| 합성 FastAPI–Semgrep E2E | PASS | `SEMGREP_REQUIRED=1 npm run test:e2e:real`; 임시 합성 프로젝트와 로컬 서비스만 사용, Semgrep 1.182.1 |
| API 실패 표현 | PASS | 합성 브라우저 네트워크 차단으로 오류 UI 확인; 실제 실패를 연결 성공으로 표시하지 않음 |
| WebKit / 실제 Safari | NOT_TESTED | 설치된 Playwright 브라우저 목록에 WebKit이 없고 Safari 수동 검수도 수행하지 않음 |
| axe / 정식 WCAG 적합성 | NOT_TESTED | axe 의존성이 없어 자동 axe 검사는 수행하지 않음. 키보드 메뉴·Escape·focus 복귀 및 focus ring은 회귀 테스트로 확인 |
| GitHub CI | NOT_VERIFIED | 작업 시작 HEAD `3722970…` 실행 없음; GitHub main은 여전히 `de83be3…` |

최종 Playwright Chromium 캡처는 1440×900, 1920×1080, 1280×800, 768×1024, 390×844를 포함한다. 시작/결과/빈 결과/상세/안내/오류/모바일 Drawer 상태는 아래 증거 목록을 참조한다. 자동화 스크린샷은 직접 열어 시각 검토했다.

## 시각 증거

- 이전 시작 화면: [before-start-1440x900](assets/ui-d2/before-start-1440x900.png)
- 새 시작 화면: [start-1440x900](assets/ui-d2/start-1440x900.png), [start-1920x1080](assets/ui-d2/start-1920x1080.png), [start-390x844](assets/ui-d2/start-390x844.png)
- 새 결과 화면: [results-1440x900](assets/ui-d2/results-1440x900.png), [results-1920x1080](assets/ui-d2/results-1920x1080.png), [results-1280x800](assets/ui-d2/results-1280x800.png), [results-768x1024](assets/ui-d2/results-768x1024.png), [results-390x844](assets/ui-d2/results-390x844.png)
- 추가 상태: [Finding 상세](assets/ui-d2/finding-detail-1440x900.png), [빈 결과](assets/ui-d2/empty-results-1440x900.png), [사용 안내](assets/ui-d2/guide-1440x900.png), [오류 상태](assets/ui-d2/api-error-1440x900.png), [모바일 메뉴](assets/ui-d2/mobile-menu-390x844.png)

검토 결과, 시작 화면의 컨트롤은 시안 B처럼 충분히 큰 2열 구조이고, 결과 화면은 요약 후 C 방식의 후보 목록/근거 검토로 이어진다. 모바일에서는 컨트롤과 요약이 세로로 재배치되며, Drawer가 열릴 때만 배경이 어두워지고 Escape로 닫힌다. 390px에서는 수직 스크롤이 필요하지만 가로 넘침은 자동화 검사에서 발견되지 않았다.

## 계약과 남은 제한

- FastAPI/CLI, Semgrep 실행, Finding/Evidence 자료형, 검증 상태, 인증 흐름, 결과 내보내기 범위 및 GitHub Intake 차단 상태를 바꾸지 않았다. API 계약은 변경하지 않았다.
- 실제 사용자 저장소나 코드를 사용하지 않았다. 합성 브라우저 테스트의 토큰은 테스트 메모리에서만 사용했다.
- 현재 로컬 API가 실행된 상태로 연결 확인을 실행했으며, 오류 화면은 테스트에서 `/health`와 `/options` 요청을 차단하여 별도로 검증했다. UI 상태를 가짜로 설정하지 않았다.
- 실제 Safari, WebKit, axe 기반 자동 접근성 감사, 사용자 최종 수용은 미완료다.
- 작업 시작부터 `App.tsx`, 테스트 파일과 이전 Phase 증거가 이미 미커밋 상태였다. 같은 파일에 이전 UI 변경과 이번 변경이 함께 있어 Phase 파일만 분리 스테이징할 수 없으므로 이번에는 커밋하지 않았다. 변경분은 로컬에 남아 있고 push하지 않았다.

**판정:** `PHASE_UI_D2_IMPLEMENTATION_REVIEW_READY` — 사용자 검수 대기. 실제 Safari 및 최종 사용자 수용을 의미하지 않는다.
