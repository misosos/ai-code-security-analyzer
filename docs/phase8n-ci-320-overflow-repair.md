# Phase 8N CI Repair — 320px 가로 넘침 복구

## 시작 Gate와 실패

- 기준 및 원격 `main`: `a4054301f81d5c335f7ae249bfc140473e0f3f33`
- GitHub Actions Run: `41788662215` (`push / completed / failure`, head SHA 일치)
- Python tests and CLI, Semgrep 1.182.1 integration: 성공
- React dashboard: 실패, Artifacts 0개
- 실패 위치: `frontend/browser-tests/webkit-compatibility.spec.ts:81`
- CI 결과: 48 passed / 1 failed. React dashboard 선행 실패 때문에 실제 FastAPI–Semgrep E2E는 실행되지 않음.
- CI 오류: `WebKit horizontal overflow at 320px` — 기대 `<= 320`, 실제 `326`

테스트 파일 이름과 달리 CI는 `.github/workflows/ci.yml`의 `npm run test:browser`를 실행하며, [Playwright 기본 설정](../frontend/playwright.config.ts)은 Chromium을 선택한다. 실제 Playwright WebKit은 별도 `playwright.webkit.config.ts` 구성으로 분리된다.

## 재현 환경과 원인

Node.js 24.22.2, Playwright 1.64.1, Debian Bookworm의 Linux AMD64 Chromium 컨테이너에서 production preview와 기존 테스트를 그대로 실행해 320px의 `scrollWidth=326`을 재현했다. 컨테이너는 Apple Silicon 호스트에서 AMD64 에뮬레이션으로 실행했다. macOS Chromium에서는 수정 전 해당 테스트가 통과했다.

320px에서의 수정 전 주요 측정값:

| 요소 | 위치 및 폭 | 계산 결과 |
| --- | --- | --- |
| `documentElement` | client 320px, scroll 326px | 페이지가 우측으로 6px 넘침 |
| `.dashboard-main` 콘텐츠 영역 | x=18~302px, 284px | 정상적으로 18px 좌우 여백을 둔 폭 |
| `.d2-results-workspace` | 폭 284px | 암시적 단일 Grid 열이 intrinsic minimum을 따라 307.703px로 확장 |
| `.scan-context` 및 결과 섹션 | x=18~325.703px | 부모의 가용 폭보다 23.703px 넓음 |
| `details.sarif-export-tool` | x=32~325.703px | 앞 문장 뒤에서 inline-block으로 배치되어 긴 SARIF 안내가 최소 콘텐츠 폭을 키움 |

결과 작업 영역은 열을 명시하지 않은 Grid였다. 열린 SARIF 내보내기 상세의 intrinsic width가 자동 Grid 열의 최소 폭을 키웠고, 결과 화면의 여러 형제 요소가 그 폭으로 늘어났다. 내부 `details` 하나의 문제처럼 보여도 실제 `scrollWidth`는 Grid의 형제 전체가 307.703px 열에 맞춰지면서 326px가 됐다. Preflight를 함께 펼친 진단에서는 그 상세 내용의 intrinsic sizing도 자동 열의 폭에 영향을 줬다.

## 수정

`frontend/src/app-shell-d5a.css`에 모바일 범위의 두 규칙을 추가했다.

- 760px 이하: `.d2-results-workspace`의 단일 열을 `minmax(0, 1fr)`로 제한해 긴 상세가 부모 Grid의 자동 최소 열 너비를 강제하지 않게 함.
- 600px 이하: SARIF 상세 접기를 앞 문장 옆 inline-block에서 별도 block 행으로 옮기고, 시작 여백을 제거함.

설명, 버튼, SARIF Preflight, Finding 위치 목록을 삭제하거나 감추지 않았다. 전역 `overflow-x: hidden`, 폰트 축소 및 테스트 기준 변경은 하지 않았다.

## 수정 후 검증

- Linux Chromium에서 수정 전 320px 실패를 재현했고, 실제 CSS 수정 후 기존 두 WebKit 호환성 테스트를 통과했다.
- 회귀 테스트는 SARIF 다운로드 후 Code Scanning Preflight와 Finding 위치 목록을 펼치고, JSON 백업 복원 미리보기를 적용한 상태에서 1920/1440/1280/1024/768/600/390/320px의 `documentElement.scrollWidth <= clientWidth`를 검사한다. 실패 시 실제 넘침 요소의 selector 및 computed layout 핵심값을 출력한다.
- 수정 후 macOS Chromium 전체: 49/49 통과.
- 수정 후 전용 Playwright WebKit: 2/2 통과.
- 320px 테스트는 Chromium과 Playwright WebKit에서 모두 통과. Linux Chromium 수정 후 재측정은 client 320px / scroll 320px, 우측 초과 요소 없음이었다. 8개 화면 폭에서 전체 페이지 수평 넘침이 없었다.
- axe-core 자동 접근성 검사 7개가 Chromium 전체 suite에서 통과했다. 자동 axe 결과는 실제 Safari/VoiceOver 검수 완료를 뜻하지 않는다.
- 기존 UI-D3 1440×900 측정: Finding 목록 Y=724.44px, 첫 Finding 행 Y=784px. 기존 기준 `<810px` 및 `<870px` 유지.

### Linux 전체 suite의 환경상 차이

Linux 컨테이너에서 전체 suite는 47 passed, 2 failed였다. 이번 overflow 테스트는 통과했다.

1. `dashboard.spec.ts`의 시작 화면 공백 측정은 44px로 기존 기준 40px 미만을 넘었다. 변경한 CSS는 결과 화면의 `.d2-results-workspace`와 SARIF 상세에만 적용된다. 동일한 실패를 기준 커밋의 CSS로 되돌린 뒤에도 재현해 이번 변경의 회귀가 아님을 확인했다.
2. axe의 Finding 결과 테스트는 AMD64 에뮬레이션에서 30초 테스트 제한 안에 끝나지 않았다. 네이티브 macOS Chromium 전체 suite에서는 해당 검사를 포함해 통과했다.

따라서 로컬 Linux 전체 suite의 위 두 상태는 통과로 기록하지 않는다. GitHub exact SHA Linux CI는 수정 커밋 Push 이후 확인해야 한다.

## 전체 회귀 결과

| 검사 | 결과 |
| --- | --- |
| Node.js | 24.22.2 |
| TypeScript typecheck | 통과 |
| Vitest | 180 passed / 15 files |
| Production build | 통과 |
| macOS Chromium 전체 Playwright | 49 passed |
| Playwright WebKit | 2 passed |
| SARIF 및 Code Scanning Preflight 브라우저 흐름 | 통과, 다운로드 추가 API 요청 없음 |
| Python 전체 (`uv run --locked`, Python 3.12.7) | 542 passed, 28 skipped, warning 1개 |
| Semgrep 통합 (`SEMGREP_REQUIRED=1`, 1.182.1) | 44 passed, warning 1개 |
| FastAPI–Semgrep–Chromium 실제 합성 E2E | 2 passed |
| Safari QA 서버 테스트 | 7 passed |
| `git diff --check` | 통과 |

Python에서 건너뛴 28건은 저장소에서 별도 opt-in을 요구하는 Ollama 합성 평가다. 경고는 Starlette TestClient 의존성의 기존 deprecation warning이다.

## 미검증 범위

- 수정 커밋의 GitHub Actions Linux exact SHA 결과: `PENDING_USER_PUSH`
- macOS Safari 실제 사용자 검수, VoiceOver, iOS Safari: 미실행
- 실제 Safari 200% 확대: 미검증
- CSS viewport 대리 검사와 Playwright WebKit은 실제 Safari 사용자 수용을 대신하지 않는다.

**사용된 화면 자료와 테스트 데이터는 합성 데이터다. 실제 GitHub Code Scanning 업로드는 수행하지 않았다.**
