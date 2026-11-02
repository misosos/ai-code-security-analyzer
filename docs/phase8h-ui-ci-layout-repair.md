# Phase 8H-UI CI 레이아웃 복구

## 범위와 시작 상태

이 변경은 Finding 목록이 Linux Chromium CI에서 승인된 화면 위치보다 아래로 밀리는 회귀만 다룬다. 기준 커밋은 `58ca8fd132667a539d85c87f72480b9c8f93fa5d`이며, GitHub Actions Run `41389059514`의 Python 및 Semgrep 작업은 성공했고 React dashboard는 브라우저 레이아웃 검사에서 실패했다. 선행 브라우저 실패 때문에 FastAPI–Semgrep E2E는 실행되지 않았다.

| 시나리오 | CI Finding 목록 Y | 요구 기준 | CI 첫 행 Y |
|---|---:|---:|---:|
| `analyst-workspace.spec.ts` (합성 Finding 2건) | 866px | `<810px` | CI 실패 로그에 별도 측정값 없음 |
| `ui-d3.spec.ts` (합성 Finding 1건) | 836.359px | `<810px` | 약 896.359px |

두 테스트는 서로 다른 합성 target 이름, Finding 수, 규칙 ID, 경로와 심각도 분포를 사용한다. 따라서 콘텐츠 줄바꿈 차이가 공통 요약 레이아웃에 누적될 수 있다. 어느 시나리오도 실제 프로젝트를 사용하지 않는다.

## 원인

기존 Linux 로그에서 `.overview-grid`는 113px, 심각도 분포는 Y=441px에 높이 59px였다. `.results-heading`은 130px로 macOS Chromium과 같았고 필터 행도 76px였다. 따라서 확인된 53px 차이는 이 공통 컨테이너들에서 발생하지 않았다. 높이 차이는 심각도 분포 아래의 분석가 검토 요약 및 비교 기준 미지정 패널 구간에 누적됐다. 당시 CI 로그는 이 두 내부 요소의 개별 bounding box를 남기지 않아 각각의 기여도를 확정할 수 없다.

- 요약 분석 행은 심각도 분포와 분석가 검토 현황을 2열로 배치한다. Linux 글꼴 메트릭에서 분석가 안내가 여러 줄로 바뀌면 행 높이가 증가한다. CI 로그의 심각도 분포 크기는 macOS와 같았고, 분석가 요약의 내부 높이는 별도로 측정되지 않았다.
- 비교 패널은 `flex-wrap`으로 콘텐츠와 기준 지정 버튼을 배치했다. 설명 문구가 길어지는 글꼴/폭 조합에서 설명과 버튼이 추가 행을 만들 수 있는 구조였다.
- 따라서 재현 가능한 원인은 Linux 폰트 메트릭과 결합된 내부 요약/비교 콘텐츠의 줄바꿈 민감성이다. 원격 로그만으로 내부 항목별 픽셀 기여도를 나누어 확정하지는 않았다. 검색/필터 알고리즘, Finding 행 자체, 텍스트 크기와 보안 상태 표현은 실패 위치보다 아래에 있으므로 원인이 아니다.

## 수정

- 분석가 안내를 `검토 상태는 취약점 확정·수정 완료가 아닙니다.`로 간결하게 바꿨다. 수동 검토 상태가 취약점 확정이나 수정 완료를 뜻하지 않는다는 의미는 유지한다.
- 넓은 화면에서 기준 미지정 비교 패널을 2열 CSS Grid로 배치해 저장 버튼이 설명과 함께 불필요하게 다음 행으로 밀리지 않도록 했다. 내부 설명은 남은 폭 안에서 자연스럽게 줄바꿈한다.
- 760px 이하에서는 패널과 내용을 기존처럼 단일 열로 재배치하고 버튼은 전체 폭을 사용한다.
- 새 브라우저 회귀 조건은 비교 패널 높이 72px 이하와 분석가 안내 한 줄 표시를 검증한다. 기존 Finding 목록 `<810px`, 첫 행 `<870px` 임계값은 유지했다.

UI 구조, 필터, 비교 조건, 데이터 계약은 바꾸지 않았다. 본문과 컨트롤 폰트 크기는 변경하지 않았다.

## 수정 전후 측정

1440×900에서 macOS Chromium은 변경 전 기준 목록 Y 약 783px, 첫 행 약 843px였으며 수정 후에도 각각 783.25px와 843px로 확인됐다. 즉 macOS에서 콘텐츠를 위로 당기거나 기존 레이아웃을 줄이지 않았다.

수정 후 Linux Chromium 대리 환경(Playwright `v1.64.1-noble`, Node `24.22.2`, 합성 앱 빌드)에서는 다음과 같이 측정됐다.

| 시나리오 | 목록 Y | 첫 행 Y | 기존 기준 대비 여유 |
|---|---:|---:|---:|
| Analyst workspace (2건) | 693px | 753px | 각각 117px / 117px |
| UI-D3 (1건) | 693.719px | 753px | 각각 약 116.281px / 117px |

이 Linux 컨테이너의 글꼴 메트릭은 GitHub runner와 일치하지 않았다. 같은 수정 후 컨테이너의 결과 제목은 114px였지만 실패했던 GitHub 측정은 130px였고, 목록 위치도 크게 다르다. 따라서 이 결과는 Linux 기반 Chromium 대리 검증의 성공으로만 기록하며 GitHub Linux runner 복구의 확정 증거로 사용하지 않는다. 정확한 GitHub runner는 새 커밋의 원격 CI로 확인해야 한다.

| 측정 요소 | macOS 수정 후 | Linux 컨테이너 대리 |
|---|---:|---:|
| `.scan-context` | 112px | 93px |
| `.scan-banner` | 65px | 56px |
| 핵심 요약 `.overview-grid` | 113px | 100px |
| 심각도 분포 | 59px | 별도 높이 미수집 |
| 분석가 검토 요약 | CI 내부 높이 미수집 | 안내 문구 1줄 조건 통과; 전체 분석 행 픽셀 높이는 이 실행에서 별도 수집하지 않음 |
| 비교 미지정 패널 | 64px | 64px 이하 조건 통과 |
| 결과 제목/필터 | 130px | 114px |
| Finding 목록 시작 | 783.25px | 693.719px (UI-D3) |
| 첫 Finding 행 | 843px | 753px |

## 검증 결과

Node.js `24.22.2`를 사용했다.

| 검증 | 결과 |
|---|---|
| 대상 두 브라우저 시나리오(macOS Chromium) | PASS, 2/2; 목록 783–783.25px, 첫 행 843px |
| TypeScript typecheck | PASS |
| Vitest 전체 | PASS, 106/106 |
| Production build | PASS |
| Chromium 전체 | PASS, 42/42 (axe, 키보드, viewport 및 UI-D3 포함) |
| WebKit | PASS, 2/2 |
| axe 접근성 | Chromium 전체 스위트의 axe 7개 화면 검사 PASS |
| QA 서버 테스트 | PASS, 7/7; 서버 수명주기 및 합성 프로젝트 확인 |
| Python 전체 | PASS, 542 passed, 28 skipped (Ollama 선택 실행 테스트) |
| FastAPI–Semgrep–Chromium 실제 E2E | PASS, 2/2; 실제 Semgrep `1.182.1`, 합성 저장소만 사용 |
| Linux Chromium 대리 | PASS, 2/2; exact GitHub runner parity는 NOT_VERIFIED |
| `git diff --check` | PASS |

실행 명령은 `mise exec node@24.22.2 -- npm run typecheck`, `mise exec node@24.22.2 -- npm test -- --reporter=dot`, `mise exec node@24.22.2 -- npm run build`, `BROWSER_TEST_PREVIEW_PORT=<고유 포트> mise exec node@24.22.2 -- npm run test:browser -- --workers=1`, `BROWSER_TEST_PREVIEW_PORT=<고유 포트> mise exec node@24.22.2 -- npm run test:browser:webkit -- --workers=1`, `mise exec node@24.22.2 -- npm run test:qa:safari`, `uv lock --check`, `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs`, `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 BROWSER_TEST_PREVIEW_PORT=<고유 포트> mise exec node@24.22.2 -- npm run test:e2e:real`, `git diff --check`이다. 브라우저 포트는 각 실행에 별도로 할당했으며 활성 Safari QA 포트를 재사용하지 않았다.

브라우저 검사에는 1920, 1440, 1280, 1024, 768, 600, 390, 320px가 포함됐다. 모바일 및 320px 수평 넘침은 관찰되지 않았다. 실제 macOS Safari 사용자 수용은 이번 CI 복구에서 실행하지 않았으며 `SAFARI_USER_ACCEPTANCE_PENDING`이다.

## 남은 확인

Linux 컨테이너는 GitHub-hosted runner의 글꼴/시스템 메트릭을 정확히 재현하지 못한다. 신규 커밋을 main에 반영한 뒤 그 exact SHA의 React dashboard가 성공해야 Linux CI 복구를 확정할 수 있다. 이 로컬 작업에서는 Push하지 않는다.
