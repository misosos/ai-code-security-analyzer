# Phase 36.9B-V — Cyberpunk / Sci-Fi HUD 시각 개선

## 작업 범위와 기준

- 작업 기준으로 지정된 SHA: `de83be32775b8503c1e907d47ddf79c89e0b05e3`
- 기준 Run: [41048835761](https://github.com/misosos/ai-code-security-analyzer/actions/runs/41048835761), push / completed / success
- 기준 Run의 head SHA는 지정 SHA와 일치한다. Python tests and CLI, Semgrep 1.182.1 integration, React dashboard(Chromium 및 실제 FastAPI–Semgrep E2E 포함) 세 job이 성공했다.
- 작업 시작 시 로컬 `main`은 `3f98ab1b2ce6d46907ec810dd5d96101991c227c`였고 `origin/main` 및 GitHub `main`은 기준 SHA였다. 로컬 HEAD에는 앞선 36.9B 커밋이 있었으며, 그 SHA를 대상으로 한 원격 CI는 확인되지 않았다. 이 로컬 작업은 보존하고 계속 진행했으며, push하지 않았다.
- 변경은 React 표현 계층, UI 테스트, 합성 브라우저 스크린샷 및 이 문서에 한정했다. API/DTO, Python 분석기, Finding/Evidence 판단, 규칙, 토큰 저장 정책, 의존성은 바꾸지 않았다.

## 사용자 피드백과 기존 화면

사용자는 다크 네온 테마는 좋아하지만 화면이 일반적인 동일 크기 직사각형 카드의 반복처럼 보이고, 공간감과 SF 게임 HUD의 조형성이 약하다고 했다. 검사 전 화면도 정보가 거의 없고 설정이 하나의 긴 띠에 밀집해 있었다.

동일한 합성 응답, 1440×900 Chromium viewport로 캡처한 이전 화면은 결과 요약과 상세까지 모두 비슷한 둥근 사각 테두리로 쌓이고, 첫 화면에 결과 목록이 거의 보이지 않았다. 비교 자료는 [`before/launch-1440x900.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/before/launch-1440x900.png), [`before/completed-1440x900.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/before/completed-1440x900.png), [`before/completed-1280x800.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/before/completed-1280x800.png), [`before/completed-390x844.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/before/completed-390x844.png)에 있다.

## 레퍼런스에서 적용한 방향

첨부한 참고 이미지는 넓은 시스템 바, 검사 설정 콘솔, 서로 다른 형태의 데이터·검토 패널, 마젠타/시안 조명과 얇은 구조선을 사용한다. 이를 복사한 배경 이미지나 예시 취약점 데이터로 사용하지 않고, 현재 실제 기능에 맞는 인터랙티브 React 화면으로 재구성했다.

공개 참고 자료는 [Graphic Design Junction의 2026 디자인 트렌드](https://graphicdesignjunction.com/2025/12/web-design-trends-of-2026/), [Magic UI 컴포넌트 문서](https://magicui.design/docs/components), [shadcn/ui 블록](https://ui.shadcn.com/blocks)이다. 비대칭 균형, 우주선 조작 매뉴얼형 구획, 절제된 Border Beam/Grid 계열 효과, 데이터 작업 화면의 계층을 시각적 참고로 삼았다. 코드, 에셋, 템플릿을 복사하거나 패키지를 도입하지 않아 외부 라이선스 코드가 번들에 추가되지 않았다.

## 구현

- **조작 콘솔:** 검사 대상·규칙·토큰·실행 버튼을 기능별 폭으로 배치하고, 중요한 모서리를 잘라낸 비대칭 프레임과 국소적인 상단/측면 광선을 적용했다. 작은 화면에서는 입력을 세로로 쌓는다.
- **검사 전 시작 화면:** 설명, 실제 검사 후 검토 흐름, 취약점 미확정 경고, 장식 전용 SVG 오브젝트를 가진 시작 패널을 추가했다. 가짜 스캔 수치·실시간 그래프·터미널 결과는 만들지 않았다. SVG는 접근성 트리에서 숨겼다.
- **결과 화면:** 요약 수치는 열린 구획선 중심으로 구성했다. Finding 목록은 왼쪽 데이터 콘솔, 선택한 항목은 별도의 절단형·레이어드 검토 HUD로 구분했다. 동일한 카드 모양과 그림자를 모든 영역에 반복하지 않는다.
- **깊이와 표면:** CSS 그라디언트/마스크/clip-path, 얇은 조명 라인, 배경 그리드를 사용했다. `-webkit-clip-path`와 마스크 미지원 시 보수적인 테두리 fallback을 제공한다. 신규 UI 라이브러리나 애니메이션 의존성은 추가하지 않았다.
- **텍스트와 오류:** 한국어 본문 및 입력 크기를 키우고, 일반 API 오류를 `role=alert` 영역에 표시한다. 오류 원문을 임의로 사용자에게 노출하지 않는다.

검사 결과가 없을 때는 시작 화면, 결과가 있을 때는 요약/목록/상세 작업 영역을 보여준다. API가 제공하지 않는 코드 원문, CWE/OWASP, Source/Sink 위치, 가상 취약점 결과를 생성하지 않는다. Finding은 계속 검토 후보이며 취약점 확정을 뜻하지 않는다.

## 시각 자료

합성 브라우저 테스트가 캡처한 비교 및 결과물:

- 시작: [`start/launch-1440x900.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/start/launch-1440x900.png), [`start/launch-390x844.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/start/launch-390x844.png)
- 완료: [`completed-1920x1080.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/completed-1920x1080.png), [`completed-1440x900.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/completed-1440x900.png), [`completed-1280x800.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/completed-1280x800.png), [`completed-768x1024.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/completed-768x1024.png), [`completed-390x844.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/completed-390x844.png)
- 세부 상태: [`finding-detail-panel.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/finding-detail-panel.png), [`filtered-high.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/filtered-high.png), [`partial-zero-1440x900.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/partial-zero-1440x900.png), [`partial-zero-390x844.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/partial-zero-390x844.png), [`request-error-1440x900.png`](assets/ui-cyberpunk-hud-refinement-36-9b-v/request-error-1440x900.png)

이미지는 실제 결과로 오해되지 않도록 고정된 합성 DTO와 테스트 전용 토큰으로 생성했다. API에서 받은 개인정보나 사용자 코드가 없다.

## 검증 결과

실행 환경은 Node 24이며 Chromium은 Playwright 브라우저다. zoom은 100%다.

- `mise exec node@24 -- npm run typecheck` — 통과
- `mise exec node@24 -- npm test` — 4개 파일, 42개 테스트 통과
- `mise exec node@24 -- npm run build` — 통과
- `mise exec node@24 -- npm run test:browser` — Chromium 5개 테스트 통과. 1920×1080, 1440×900, 1280×800, 768×1024, 390×844 레이아웃, 가로 넘침, 키보드·토큰 비저장, 검색·필터/선택 및 상태별 캡처 포함
- `SEMGREP_REQUIRED=1 mise exec node@24 -- npm run test:e2e:real` — Chromium–FastAPI–Semgrep 합성 E2E 1개 통과
- `git diff --check` — 통과
- WebKit 실행 파일이 설치되어 있지 않아 Playwright WebKit은 시작되지 않았다. WebKit 및 실제 Safari 검수는 **NOT_TESTED**다. WebKit 설치/다운로드는 하지 않았다.
- axe 실행 패키지가 없어 자동 axe 검사는 **NOT_TESTED**다. 대비 비율을 수치로 재지 않았으며 WCAG AA 적합성을 선언하지 않는다. 기존 접근성 테스트와 브라우저 확인에서는 label, 키보드 조작, 상태 alert, 장식 SVG 숨김, viewport 넘침, reduced-motion 규칙을 확인했다.
- 실제 Safari 사용자 검수 및 사용자 디자인 수용은 별도이며 완료로 간주하지 않는다.

1440×900 결과 화면은 요약과 Finding 작업 영역을 같은 첫 화면에 더 많이 배치한다. 1280×800에서는 Finding 목록의 시작 부분과 상세 패널 상단이 보이지만, 모든 상세 내용을 첫 화면에 넣지는 않는다. 모바일은 목록과 상세를 세로 배치한다.

## 남은 한계와 판정

WebKit/Safari, 자동 대비 측정 및 실제 사용자의 최종 디자인 수용은 미검증이다. 본 작업의 브라우저 수용 기준은 Chromium 시각 검수까지다.

판정: **`PHASE_36_9B_V_VISUAL_REVIEW_READY`** — 실제 UI의 패널 형태·시작 화면·결과 작업 영역을 변경했고, 스크린샷 비교와 지정된 Chromium 회귀가 완료됐다. 이는 실제 사용자의 최종 수용을 뜻하지 않는다.
