# Phase 8H-UI — 보안 분석가 작업 공간 UX 개선

## 목적과 시작 Gate

실제 Safari 화면에서 확인한 검색·필터 정렬, 요약 정보 밀도, 기준 없는 비교 패널의 공간 점유, Finding 정보 계층 문제를 정리했다. 검증된 시작 기준은 `882a68367c8c6b5b1a8a9b9d6a51e349a58a9053`이며, 해당 SHA의 `push / completed / success` CI Run `41331955925`에서 Python, Semgrep 1.182.1, React dashboard, 실제 FastAPI–Semgrep E2E가 성공했고 Artifact는 0개였다. 작업은 `phase/8h-ui-workspace` 격리 worktree에서 수행했다.

기능 범위는 프런트엔드 작업 공간 정리에 한정한다. FastAPI 계약, CLI, Semgrep 규칙, Finding/Evidence DTO, 검증 상태, 비교 알고리즘, Markdown/JSON 포맷, 세션 메모리 저장 정책은 변경하지 않았다.

## 정보 구조 변경

- 검사 문맥에서 프로젝트와 규칙 프로필 이름을 먼저 보여주고, 내부 ID와 브라우저 수신 시각을 보조 행에 배치했다. 결과 및 검토 기록 내보내기, JSON 백업/복원, 결과 삭제 동작은 그대로 유지했다.
- 검토 후보·표시 결과·생략 결과를 세 개의 핵심 수치로 묶고, 심각도 분포와 분석가 검토 현황을 별도 분석 그룹에 배치했다. 검토 현황에는 수동 상태가 취약점 확정이나 수정 완료를 뜻하지 않는다는 안내를 표시한다. Semgrep 심각도에도 악용 여부 미확인 안내가 남아 있다.
- 기준이 없는 정상 완료 검사에는 짧은 비교 기준 안내와 기준 지정 버튼만 표시한다. 기준이 생기면 기존 비교 범주와 보고서 버튼을 유지한다. 부분 검사 및 실제 비교 차단 조건은 기존 차단 이유를 계속 표시한다.
- Finding 제목, 심각도, 파일 위치, 규칙 ID, 탐지/검증 상태, 분석가 검토 상태 순서로 정보를 정리했다. Finding 선택은 `aria-pressed`, Cyan 테두리/배경 및 키보드 포커스로 표현한다. 긴 경로와 규칙 ID는 줄바꿈할 수 있다.

검색 Toolbar는 `검색`, `분석가 검토`, `심각도`, `탐지 유형`, `검증 상태` 다섯 컨트롤로 구성했다. 시각적 레이블과 accessible name을 일치시키고, 입력 필드와 선택 컨트롤을 같은 높이로 정렬했다. 넓은 화면에서는 한 줄, 1024–1300px에서는 균형 있는 2행, 760px 이하에서는 2열, 380px 이하에서는 1열로 배치한다. 기존 필터 알고리즘은 그대로 사용한다.

## 시각 검증 자료

모든 화면은 브라우저 테스트에서 구성한 합성 Finding으로 생성했다. 스크린샷을 직접 확인했으며, 새 보고서의 실제 macOS Safari 검수는 아직 수행하지 않았다.

- [1440×900, 기준 없음](assets/ui-h8-ui/results-1440x900-baseline-none.png)
- [1440×900, 기준 지정](assets/ui-h8-ui/results-1440x900-baseline-set.png)
- [1280×800 결과](assets/ui-h8-ui/results-1280x800.png)
- [390×844 결과](assets/ui-h8-ui/results-390x844.png)
- [Finding 상세](assets/ui-h8-ui/finding-detail-1440x900.png)

1440×900 Chromium UI-D3 회귀에서 Finding 목록 시작점은 document Y `783.25px`, 첫 행은 `843.25px`로 측정되어 기존 기준 `Y < 810px`, `Y < 870px`를 각각 통과했다. 1280×800, 1024×768, 768×1024, 600×800, 390×844, 320×800에서도 Toolbar 문서 폭은 viewport와 같았고 가로 넘침은 0이었다. 실제 Safari에서 확인한 확대 배율은 없다. Playwright의 320px CSS viewport 대리 검증은 통과했으며 실제 200% Safari 확대와는 구분한다.

## 접근성과 타이포그래피

axe 검사를 검사 시작, 결과/상세, 복원 미리보기, 비교, 사용 안내, 오류·부분 검사·0건 상태에 적용한다. Toolbar 필터는 명시적 레이블을 제공한다. 키보드 전용 브라우저 시나리오와 모바일 Drawer 포커스/닫기 동작을 확인한다. 새 CSS는 본문이나 제목을 축소하지 않으며, 탐지 제목 19px, 입력/필터 18px, 페이지 제목 기존 크기를 유지한다.

## 검증 결과

환경은 macOS, Node.js `24.22.2`(mise), Semgrep `1.182.1`이다. Playwright Chromium과 Playwright WebKit은 각각 별도 브라우저 실행으로 확인했다. Playwright WebKit 결과를 실제 macOS Safari 결과로 간주하지 않는다.

- `mise exec node@24.22.2 -- npm run typecheck`: PASS
- `mise exec node@24.22.2 -- npm test -- --reporter=dot`: PASS, 11개 파일 / 106개 테스트
- `mise exec node@24.22.2 -- npm run build`: PASS
- `BROWSER_TEST_PREVIEW_PORT=45444 mise exec node@24.22.2 -- npm run test:browser -- --workers=1`: PASS, Chromium 전체 42개 테스트. UI-D3와 axe 포함, 1440px 목록 Y `783.25px`, 첫 행 Y `843.25px`.
- `BROWSER_TEST_PREVIEW_PORT=45445 mise exec node@24.22.2 -- npm run test:browser:webkit -- --workers=1`: PASS, Playwright WebKit 2개 테스트.
- `uv lock --check && uv run --locked python -m pytest -q -rs`: PASS, 542 passed / 28 skipped. Skip은 선택적 Ollama 평가 테스트다.
- `semgrep --version`: PASS, `1.182.1`.
- CI Semgrep 핵심 통합 pytest 그룹: PASS, 44개 테스트. 벤치마크 그룹 17개, Phase 6D 1개, Phase 6E 1개 모두 PASS.
- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24.22.2 -- npm run test:e2e:real`: 1차 실행 1/2 실패. 문서 계층 변경 후 테스트가 표시 이름과 내부 ID가 연속 문자열일 것을 가정한 locator가 원인이었다. 이름과 ID를 각각 확인하도록 검증을 보완한 뒤 재실행: PASS, 2/2.
- `mise exec node@24.22.2 -- npm run test:qa:safari`: 1차 실행 6/7 PASS. 테스트가 접속 주소 출력만으로 서버 준비를 판정해 토큰 줄이 늦게 도착하는 stdout 경쟁 조건이었다. 주소와 토큰 준비 표식 모두를 확인하도록 테스트 readiness를 고친 뒤 재실행: PASS, 7/7. QA 실행 로직 및 토큰 정책은 변경하지 않았다.
- `git diff --check`: PASS.
- Linux Chromium: `NOT_VERIFIED`(이번 로컬 실행 환경은 macOS). 사용자의 Push 이후 exact SHA 원격 CI가 필요하다.
- 실제 macOS Safari 및 실제 브라우저 200% 확대: `NOT_TESTED`; 사용자가 Safari 검수를 완료하고 명시적으로 수용할 때까지 `SAFARI_USER_ACCEPTANCE_PENDING`.
- VoiceOver 및 iOS Safari: `NOT_TESTED`.

기존 비교, 검토 상태, 메모, 보고서/백업, API 요청 동작 회귀 테스트는 유지했다. 자동화는 실제 Safari 호환성, 분석 정확도, 취약점 해결 여부를 보증하지 않는다.

브라우저 테스트가 기존 `docs/assets/` 캡처를 갱신했으나 해당 테스트 산출물은 커밋 범위가 아니며, 시작 시점의 깨끗한 worktree 파일로 복원했다. 신규 Phase 스크린샷은 합성 데이터만 포함한다.
