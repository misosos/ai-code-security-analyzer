# Phase 8H-UI CI Repair 2 — 결과 레이아웃 회귀 복구

## 시작 Gate

- 저장소: `misosos/ai-code-security-analyzer`
- 기준 `origin/main`: `c783d2d7f37115289f8fc9d953bcf70b242809de`
- GitHub Actions: Run `41401872705`, `push / completed / failure`
- Python tests and CLI: 성공
- Semgrep 1.182.1 integration: 성공
- React dashboard: 실패 (Chromium 42 PASS / 1 FAIL)
- 실제 FastAPI–Semgrep E2E: 선행 브라우저 실패로 건너뜀
- Artifacts: 0
- 작업 브랜치: `phase/8h-ui-ci-repair2`
- 작업 worktree: `/tmp/ai-csa-phase8h-ui-ci-repair2`

기존 Desktop 작업, 다른 worktree 및 사용자 QA 서버에는 변경을 가하지 않았다.

## 실패 및 원인

실패한 `analyst-workspace.spec.ts`는 두 Finding(높음 1, 중간 1)과 한국어 프로젝트 표시명 `합성 분석 프로젝트`를 사용한다. 통과한 UI-D3 시나리오는 Finding 1건(높음)과 영문 표시명 `Synthetic Review Project`를 사용한다. 둘 다 기준 없음 compact 비교 상태이며, 1440×900에서 결과 제목·검색/필터·목록을 같은 구조로 렌더링한다.

GitHub Linux 측정은 분석 요약 영역 높이 185px, Finding 목록 Y=814px, 첫 행 Y=874px였다. 기존 macOS Chromium은 두 시나리오에서 주요 영역 높이가 같았고, 목록 Y≈787.5px, 첫 행 Y≈847.5px였다. Linux에서 분석 요약의 intrinsic grid 높이가 약 30px 더 커진 만큼 이후 문서 흐름의 목록과 첫 행도 같은 양만큼 밀렸다. 비교 패널이나 필터 데이터는 두 시나리오에서 같은 구조이고, Finding 개수 차이는 목록 아래 높이에만 영향을 준다.

레이아웃에는 심각도 항목의 `flex-wrap`, 분석 요약 카드의 콘텐츠 기반 행 크기, 넉넉한 세로 padding/min-height가 함께 있었다. 글꼴 fallback에 따른 텍스트 너비와 줄바꿈이 달라질 때 이 콘텐츠 기반 행 높이가 커질 수 있다. 수집된 GitHub 로그에는 해당 런의 개별 자식 bounding box가 없으므로 어느 한 텍스트 노드의 줄바꿈만이 원인이라고 단정하지 않는다. 복구는 이 변동이 결과 목록까지 전달되지 않도록 공통 결과 화면의 불필요한 세로 여백을 줄이는 방식으로 했다.

## 변경 내용

`app-shell-d5a.css`에서 데스크톱 결과 화면에 한정해 다음 간격을 조정했다.

- 핵심 지표 최소 높이 88px → 76px, 세로 padding 8px → 6px
- 분석 요약 세로 padding 8/10px → 4/6px
- compact 비교 영역 margin 4/9px → 3/5px, 세로 padding 8px → 5px
- 결과 제목/필터 묶음 gap 7px → 4px, 위·아래 margin 8/10px → 4/6px

폰트 크기, 내용, 비교 상태, Finding 목록/상세 구조, UI-D3의 기존 `<810px` 및 `<870px` 검증 기준은 유지했다. 숨김, clipping, 음수 margin, transform은 사용하지 않았다.

## 1440×900 측정

| 시나리오 | 기준선 macOS 목록/첫 행 | 수정 후 macOS 목록/첫 행 | GitHub Linux 실패 측정 |
|---|---:|---:|---:|
| Analyst workspace (Finding 2건) | 787.5 / 847.5px | 749 / 809px | 814 / 874px |
| UI-D3 (Finding 1건) | 787.5 / 848px | 749.25 / 809px | 목록 784px (통과) |

수정 후 두 macOS 시나리오 모두 기존 기준보다 충분히 위에 있고, 새 회귀 검사로 목록 `<790px`, 첫 행 `<850px`의 여유도 확인한다. 이 강화된 검사는 기존 기준을 대체하지 않는다.

수정 후 macOS 주요 computed heights:

| 영역 | 높이 | 세로 여백/패딩 |
|---|---:|---|
| 검사 문맥 `.scan-context` | 111.63px | padding 8/8px |
| 검사 결과 배너 `.scan-banner` | 65px | padding 8/8px |
| 핵심 지표 `.analyst-overview-core` | 108.59px | padding 5/5px |
| 분석 요약 `.overview-analysis-grid` | 146.38px | padding 4/6px |
| 분석가 현황 `.analyst-review-summary` | 135.38px | 내부 padding 4/4px |
| 심각도 분포 `.severity-counts` | 59.38px | margin 5/3px |
| 비교 영역 `.scan-comparison-compact` | 58px | margin 3/5px, padding 5/5px |
| 제목 및 필터 `.results-heading` | 126.59px | gap 4px, margin 4/6px |
| 필터 `.filter-row` | 76.30px | 컨트롤 높이 48px 유지 |

macOS computed body/main font는 20px, line-height 33px로 유지됐다.

## Linux 재현

Node 24.22.2와 Playwright 1.64.1이 포함된 Linux x64 컨테이너에서 두 대상 테스트 9개를 통과했다. 해당 컨테이너의 1440px 목록/첫 행은 653/713px였고, body/main line-height가 20px였다. 이는 GitHub Actions의 보고 좌표와 다른 브라우저 스타일 환경이므로 GitHub-hosted Linux의 재현 또는 최종 성공 근거로 간주하지 않는다. 신규 커밋에 대한 원격 CI 결과가 Linux 최종 확인이다.

Linux 컨테이너 준비 중 이미지에 `xz`가 없어 첫 압축 해제가 실패했고, Node 아카이브 경로 설정 오류로 한 차례 잘못된 Node 26이 선택됐다. 검증된 Node 24.22.2 gzip 아카이브와 올바른 PATH로 다시 실행해 targeted tests를 통과했다. 이 설정 실패는 제품 테스트 실패가 아니다.

## 검증 결과

- `mise exec node@24.22.2 -- npm run typecheck`: PASS
- `mise exec node@24.22.2 -- npm test -- --reporter=dot`: PASS, 106 tests
- `mise exec node@24.22.2 -- npm run build`: PASS
- `BROWSER_TEST_PREVIEW_PORT=43875 mise exec node@24.22.2 -- npm run test:browser -- --reporter=line`: PASS, Chromium 43 tests; axe 7개 포함
- `BROWSER_TEST_PREVIEW_PORT=43877 mise exec node@24.22.2 -- npm run test:browser:webkit -- --reporter=line`: PASS, WebKit 2 tests
- `mise exec node@24.22.2 -- npm run test:qa:safari`: PASS, 7 tests (서버 시작/종료, 인증, 합성 프로젝트, 정리)
- `uv lock --check`: PASS
- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs`: PASS, 542 passed, 28 skipped, 1 경고
- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 BROWSER_TEST_PREVIEW_PORT=43879 mise exec node@24.22.2 -- npm run test:e2e:real`: PASS, 실제 FastAPI–Semgrep–Chromium 2 tests; Semgrep 1.182.1
- `git diff --check`: 최종 단계에서 확인

Chromium 전체 테스트에는 1920/1440/1280/1024/768/600/390/320px 레이아웃 검증, 모바일 Drawer, UI-D3, 추가 안내 정렬 및 axe 접근성 검사가 포함된다. 실제 Safari 사용자의 수용 검수는 수행하지 않았다.

## 남은 확인

- GitHub-hosted Linux에서 신규 커밋의 정확한 CI 결과
- 실제 macOS Safari 사용자 수용
- Safari 사용자 승인 상태: `SAFARI_USER_ACCEPTANCE_PENDING`
