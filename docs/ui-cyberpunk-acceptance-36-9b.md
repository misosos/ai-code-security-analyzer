# Phase 36.9B — 사이버펑크 대시보드 사용자 검수 준비

## 판정

`PHASE_36_9B_USER_REVIEW_READY`

브라우저에서 확인할 수 있는 검수 환경과 합성 결과를 준비했다. 자동화 검증은 통과했지만, 실제 사용자가 평가한 항목은 아직 없다. 사용자 수용 검수 10개 항목은 모두 `NOT_TESTED`이며 `USER_ACCEPTED`가 아니다.

## 시작 Gate

- 저장소 `misosos/ai-code-security-analyzer`, 브랜치 `main`
- 기준 SHA: `de83be32775b8503c1e907d47ddf79c89e0b05e3`
- 로컬 HEAD, `origin/main`, GitHub `main` 일치
- 시작 시 working tree clean, ahead/behind `0/0`
- 요청에 기재된 Run `41040899993`의 실제 head SHA는 이전 커밋 `0caabcc77752016bd3f24b9e75d6388c91fdd16c`였다. 기준 SHA에 해당하는 실제 성공 Run은 `41048835761`이다.
- 기준 Run: `push`, `completed`, `success`. Python tests and CLI, Semgrep 1.182.1 integration, React dashboard, 실제 Chromium–FastAPI–Semgrep E2E 필수 job 성공
- 이 CI 결과는 기준 커밋에 대한 결과다. 이번 Phase의 로컬 수정은 새 CI를 실행하지 않았으며 원격 CI 검증을 받은 것으로 기록하지 않는다.

## 검수 환경 및 실제 분석 확인

- 환경: macOS Apple Silicon, Node.js `24.22.2`, Playwright Chromium, 브라우저 zoom 100%
- viewport: `1920×1080`, `1440×900`, `1280×800`, `768×1024`, `390×844`; 가로 넘침 검사에는 `320×780`도 포함했다.
- 현재 대시보드는 로컬 `http://127.0.0.1:5173/`, 임시 FastAPI는 loopback `127.0.0.1:8765`에서 제공한다. 프로젝트 A/B와 규칙은 합성 fixture 및 저장소의 신뢰된 로컬 규칙만 사용한다.
- 실제 브라우저에서 합성 프로젝트 B와 `Experimental Command Injection`을 선택해 Semgrep OSS `1.182.1`을 실행했다. FastAPI 응답은 `completed`, Finding 1건, `command.js:3`, `verification_status=unverified`였다. 해당 Finding은 실제 취약점 확정이 아니다.
- 실제 API 검수와 별개로 화면 캡처에는 상태별 고정 Mock 응답이 있다. Mock 캡처는 실제 Semgrep 결과가 아니다.
- API 토큰은 OS 임시 디렉터리 안의 권한 제한 파일에 생성했으며 문서와 스크린샷에 값을 기록하지 않았다. UI에서는 password input으로 표시되고 메모리에서만 보관된다. 사용자가 브라우저에 직접 입력할 때만 로컬 토큰 파일을 읽는다.
- 검수 fixture의 코드는 정적 검사 입력일 뿐 실행하지 않았다. 사용자 프로젝트 및 원격 저장소는 사용하지 않았다.

## 확인한 문제와 수정

변경 전 36.9A 합성 캡처에서 필터 제목은 `10px`, 목록 경로는 `13px`, 필터 입력은 `12px`, 분석 설명 일부는 `11–12px`였다. 전체 화면의 경고 문구도 상단과 결과 요약에서 반복됐다. PC 레이아웃 자체는 넓게 배치됐지만, 이 작은 글자 크기는 실제 검토 중 읽기 부담이 될 수 있었다.

- 검사 대상/규칙/토큰 label을 `14px`, 입력 컨트롤을 `14px`로 키웠다.
- 필터 label을 `12px`, 필터 입력을 `13px`로 키웠다.
- Finding 경로를 데스크톱 `14px`, 작은 화면 `13px`로 키우고 상세 설명을 `13px`로 조정했다.
- Finding이 취약점 확정이 아니라는 핵심 안내는 결과 요약에 남기고, 반복 문구는 선택 항목의 위치와 제한을 확인하라는 행동 안내로 바꿨다.
- 페이지 너비, 패널 구조, 분석 상태, 인증·내보내기 동작, API 및 Finding/Evidence 계약은 변경하지 않았다.

### 변경 전후 화면

아래 `전`/`후` 캡처는 같은 Phase 36.9B 합성 응답, viewport, 검사 상태와 Finding 선택으로 촬영했다. `전` 캡처에는 36.9A의 이전 글자 크기와 반복 안내 문구를 브라우저에서 적용했고, `후`에는 이번 실제 CSS와 문구를 적용했다. 따라서 이 자료는 지정한 UX 조정의 시각 비교이며, 서로 다른 데이터를 쓴 36.9A 원본 캡처와 직접 비교하지 않는다. 모든 캡처는 합성 데이터다.

| 화면 | 변경 전 | 변경 후 |
| --- | --- | --- |
| 1440×900 완료 | [전](assets/ui-cyberpunk-acceptance-36-9b/before/completed-1440x900.png) | [후](assets/ui-cyberpunk-acceptance-36-9b/completed-1440x900.png) |
| 1280×800 완료 | [전](assets/ui-cyberpunk-acceptance-36-9b/before/completed-1280x800.png) | [후](assets/ui-cyberpunk-acceptance-36-9b/completed-1280x800.png) |
| 1920×1080 완료 | — | [후](assets/ui-cyberpunk-acceptance-36-9b/completed-1920x1080.png) |
| 390×844 모바일 | [전](assets/ui-cyberpunk-acceptance-36-9b/before/completed-390x844.png) | [후](assets/ui-cyberpunk-acceptance-36-9b/completed-390x844.png) |
| 실 Semgrep 합성 Finding | — | [FastAPI–Semgrep 실제 실행, 1440×900](assets/ui-cyberpunk-acceptance-36-9b/real-semgrep-synthetic-1440x900.png) |
| 필터/상세 | — | [필터](assets/ui-cyberpunk-acceptance-36-9b/filtered-high.png), [상세](assets/ui-cyberpunk-acceptance-36-9b/finding-detail-1440x900.png) |
| 부분 검사 + 0건 | — | [1440×900](assets/ui-cyberpunk-acceptance-36-9b/partial-zero-1440x900.png), [390×844](assets/ui-cyberpunk-acceptance-36-9b/partial-zero-390x844.png) |

자동 시각 검토에서는 1280×800의 검사 대상 선택 상자에서 긴 표시 이름이 일부 잘리는 것을 확인했다. 실제 선택 값과 Finding 결과는 정상이며, 이번 Phase에서는 임의로 프로젝트 label이나 ID 표시 계약을 바꾸지 않았다. 데스크톱은 첫 화면에 상태·요약·Finding 목록과 상세의 시작 부분이 보인다. 5건 이상에서는 목록과 상세 내부 스크롤이 남고, 모바일에서는 설정과 결과가 세로로 이어져 페이지 스크롤이 필요하다.

## 브라우저·기능 및 접근성 검증

- 기준 전 수정 전 Vitest 4개 파일/42개 테스트, typecheck, build, Playwright Chromium 4개 테스트 통과
- 수정 후 `npm run typecheck`: 통과
- 수정 후 `npm test`: 4개 파일/42개 테스트 통과
- 수정 후 `npm run build`: 통과
- 수정 후 `npm run test:browser`: Chromium 5개 테스트 통과. 5개 viewport 가로 넘침과 첫 화면 배치 확인, 주요 UI 글자 크기 하한 검사, 토큰 입력 키보드 접근, 결과/필터/내보내기/초기화 확인, 합성 상태별 스크린샷 생성 포함
- 수정 후 `SEMGREP_REQUIRED=1 npm run test:e2e:real`: 실제 Chromium–FastAPI–Semgrep E2E 1개 통과. 테스트 전용 synthetic repository/rule만 사용
- 추가 loopback 실사용 확인: API 응답 200, Semgrep `1.182.1`, 완료, 합성 Finding 1건, `unverified`; token과 canary는 페이지 텍스트에 없음
- 키보드 focus, label 및 토큰 지우기 버튼 접근은 Chromium 검사로 확인했다. 대비 색상은 36.9A에서 검토한 토큰을 유지했다.
- axe 패키지는 기존 의존성에 없어 실행하지 않음 (`NOT_TESTED`). Playwright WebKit 바이너리도 설치되어 있지 않아 WebKit 실행 `NOT_TESTED`; 실제 macOS Safari 수동 검수도 `NOT_TESTED`다. Chromium 성공을 Safari 검수 완료로 간주하지 않는다.
- 전체 WCAG AA 적합성 인증은 하지 않았다. 확대율 조합별 수동 검수도 `NOT_TESTED`다.
- Python 테스트는 이번 변경이 React/CSS/브라우저 테스트 및 문서에 한정되어 실행하지 않음 (`NOT_TESTED`).

## 사용자 수용 검수 10개 항목

아래는 자동 검사 결과가 아니라 실제 사용자가 브라우저에서 직접 판단할 항목이다. 현재 사용자의 응답은 아직 기록되지 않아 전부 `NOT_TESTED`다.

| # | 검수 질문 | 사용자 결과 | 사용자 원문/메모 |
| --- | --- | --- | --- |
| 1 | PC 화면을 충분히 넓게 활용하는가? | NOT_TESTED | — |
| 2 | 첫 화면에서 검사 실행과 결과를 쉽게 찾을 수 있는가? | NOT_TESTED | — |
| 3 | 글씨 크기와 색상 대비가 편안한가? | NOT_TESTED | — |
| 4 | 네온·홀로그램 디자인이 원하는 분위기인가? | NOT_TESTED | — |
| 5 | 스크롤과 화면 이동이 불편하지 않은가? | NOT_TESTED | — |
| 6 | Finding 목록을 쉽게 비교하고 선택할 수 있는가? | NOT_TESTED | — |
| 7 | 선택 항목의 근거와 제한을 쉽게 이해할 수 있는가? | NOT_TESTED | — |
| 8 | 검색·필터·다운로드·초기화 기능이 정상 동작하는가? | NOT_TESTED | — |
| 9 | 검사 상태와 미검증 의미가 혼동되지 않는가? | NOT_TESTED | — |
| 10 | 전체적으로 실제 사용할 만한 완성도인가? | NOT_TESTED | — |

실제 응답이 오면 원문 그대로 기록하고 해당 문항만 `PASS` 또는 `FAIL`로 갱신한다. 답이 없거나 질문을 진행하지 않은 항목은 계속 `NOT_TESTED`다.

## 남은 제한 및 다음 행동

1. 사용자는 데스크톱 브라우저에서 `http://127.0.0.1:5173/`을 열고 API 토큰 파일을 로컬 터미널에서 확인해 직접 입력한다. 합성 프로젝트 B와 `Experimental Command Injection`을 선택하고 `검사 실행`을 누르면 실제 Semgrep 합성 Finding을 확인할 수 있다. 완료·검색/필터·상세 근거·제한·내보내기·결과 지우기를 직접 검토한다.
2. Safari 수동 검수가 별도로 필요하다. 현재 서버 검수 환경은 Chromium 기반이며 WebKit은 설치되어 있지 않다.
3. 자동 테스트 통과는 사용자 수용이나 전체 접근성 적합성의 증거가 아니다.
4. 부분/실패 Mock 화면은 고정 테스트 응답으로 만든 스크린샷이며 실제 장애 원인이나 실제 검사 결과를 입증하지 않는다.

## 변경 파일

- `frontend/src/styles.css`
- `frontend/src/app/App.tsx`
- `frontend/src/app/BeginnerGuidance.tsx`
- `frontend/browser-tests/dashboard.spec.ts`
- `docs/ui-cyberpunk-acceptance-36-9b.md`
- `docs/assets/ui-cyberpunk-acceptance-36-9b/` (합성 캡처)

API, CLI, 분석 엔진, 규칙, Finding/Evidence 계약, 인증 저장 방식, 기존 의존성은 변경하지 않았다.
