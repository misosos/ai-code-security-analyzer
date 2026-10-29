# Phase 6K — 초보 사용자용 보안 대시보드 UX

## 목표와 범위

기준 SHA는 `171adab2483a415537a77b9511f3f22a9b67de71`이다. Phase 6J에서 사용자가 로컬 API 토큰, 규칙 프로필, Finding, 부분 검사 및 근거 검증 상태를 이해하기 어렵다고 보고했다. 이번 변경은 그 어려움을 바탕으로 React 화면의 설명과 정보 배치를 개선한다.

Python 분석 엔진, Semgrep 규칙, Finding/Evidence/Gate/Consumer, API 및 CLI 계약, 기존 Markdown export 계약, 의존성/lockfile은 변경하지 않았다. GitHub 저장소 URL 분석, 임의 폴더 접근, 업로드, 서버 자동 실행은 추가하지 않았다.

## 시작 Gate

| 확인 항목 | 결과 |
| --- | --- |
| 저장소 / remote | `misosos/ai-code-security-analyzer` / `https://github.com/misosos/ai-code-security-analyzer.git` |
| branch 및 기준 SHA | `main`, `171adab2483a415537a77b9511f3f22a9b67de71` |
| 시작 HEAD / `origin/main` / 원격 `main` | 기준 SHA와 일치 |
| 시작 작업 트리 및 ahead/behind | clean, 0/0 |
| GitHub Actions | Run `40883686283`, 해당 SHA의 `push / completed / success` |
| 필수 CI | Python/CLI, Semgrep OSS 1.182.1, React typecheck/test/build, Chromium smoke, 필수 실제 Chromium–FastAPI–Semgrep E2E 성공 |
| 실행 환경 | uv Python 3.12.7, Node.js 24.22.2, npm 11.19.1, Semgrep OSS 1.182.1 |

원격 Run에는 artifact가 없었다. 별도 원격 실행을 성공으로 추정하지 않았다.

## 변경 내용

### 처음 시작하기

접기/펼치기 안내는 API 연결 상태와 관계없이 첫 화면에 보인다. 등록된 로컬 프로젝트 준비, FastAPI 실행, 토큰 입력, 허용 Origin, target/profile 선택, 실행 및 결과 확인 순서를 안내한다. 빌드된 FastAPI 동일 출처 화면과 Vite 개발 화면의 명령을 분리하고, 저장소 루트에서 `uv sync --locked --dev`를 실행하도록 안내한다.

토큰 예시는 Python `secrets.token_urlsafe(48)`로 난수를 생성하고 로컬 터미널에서만 확인하게 한다. 실제 토큰을 번들이나 문서에 넣지 않는다. 서버는 UI가 실행하지 않으며, `AI_CODE_SECURITY_TARGET`, `AI_CODE_SECURITY_API_TOKEN`, `AI_CODE_SECURITY_ALLOWED_ORIGINS` 환경변수와 loopback 주소를 설명한다.

### 토큰 및 검사 설정

토큰 도움말은 로컬 서버 요청 인증에 쓰이는 비밀값이며 서버에 설정된 값과 같아야 한다고 설명한다. GitHub 커밋·공유 금지, 새로고침 시 화면 값 소실, 지우기 동작은 화면의 메모리 값만 지우고 서버 설정은 바꾸지 않는다는 점을 안내한다. 입력은 계속 password 필드이며 요청의 `X-Local-API-Token` 헤더에만 전달된다.

검사 대상은 서버에 미리 등록된 프로젝트 중 하나라는 점, 규칙 프로필은 함께 실행할 규칙 묶음이라는 점을 설명한다. Experimental 프로필은 일반적인 정확도가 충분히 검증된 상태가 아니라고 명시한다. 선택지는 기존 `/api/v1/options` 응답에서만 채운다.

### 결과 요약 및 용어

완료·부분·실패·완료 0건 메시지는 API의 `scan_status`, `completed`, Finding 수에 따라 구분한다. Finding이 있어도 실제 취약점은 미확정이고, 0건도 안전 증명이 아니다. Severity는 도구 분류다. 기존 총계, 표시/생략 건수, 심각도 집계와 표시된 결과에만 적용되는 필터는 유지한다.

용어 도움말에는 Finding, Severity, Unverified, Validated Evidence, Taint, Source, Sink, Trace, Sanitizer, 규칙 프로필을 쉬운 문장으로 설명한다. Source/Sink 선언은 실제 코드 위치 확인이 아니며, Trace 부재는 흐름 부재가 아니고, 근거 연결 검증은 취약점 확정이 아니라는 제한을 함께 표시한다.

### 상태 코드 설명

API DTO에 허용된 모든 issue 및 limitation 코드는 고정 한국어 제목, 확인된 상태 설명, 다음 행동으로 안내한다. 원시 코드는 접을 수 있는 기술 상세에 보존한다. 알 수 없는 코드에는 원인을 추측하지 않고 “현재 제공된 정보만으로 자세한 원인을 확인할 수 없습니다”라고 안내한다. 새 API 필드나 오류 추론은 추가하지 않았다.

### Finding 기본/기술 상세

기본 화면은 읽기 쉬운 규칙 설명, 심각도 한국어 표기, “미검증 후보”, 상대 파일/매치 위치, 다음 검토 작업 및 위치와 흐름의 제한을 우선 제공한다. 규칙 ID는 목록에서 보조 식별자로 유지하고 상세 기술 영역에도 표시한다.

닫힌 기술 상세에는 Finding ID, 원래 rule ID, kind, evidence validation 상태, 서버가 반환한 supported/restricted claims, 결정/사유 코드가 있다. Supported claims는 기존 조건인 `evidence_validation_status === 'validated'`에서만 표시하며 프론트엔드에서 판단을 승격하지 않는다. 제한과 미검증 상태는 상세가 닫혀 있어도 기본 화면에서 확인할 수 있다.

접근성은 기존 label을 유지하고 `<details>/<summary>`의 키보드 조작, 요약 요소의 focus outline, 토큰 설명의 `aria-describedby`, 기존 `role=alert/status`를 보존한다. 레이아웃은 720px/380px 이하 규칙을 추가해 작은 화면에서 카드와 긴 식별자를 줄바꿈한다. API 문자열은 React text node로 렌더링하며 동적 HTML은 사용하지 않는다.

## 보안 및 계약 불변성

- API endpoint, DTO, target/profile ID 및 정책, 인증 헤더, 저장 방식은 변경하지 않았다.
- 토큰은 React 메모리에서만 유지되며 URL, body, cookie, localStorage, sessionStorage에 저장하지 않는다.
- 원본 코드, 절대 경로, stderr, raw Semgrep JSON 및 비밀정보를 새로 렌더링하지 않는다.
- UI는 서버가 반환한 supported/restricted claim과 validation 상태를 그대로 소비한다.
- 규칙, SemgrepAdapter, 60초 timeout, 2 MiB 출력 제한, Python 및 Node 의존성과 lockfile을 변경하지 않았다.

## TDD 및 검증

기존 프론트엔드 baseline은 Vitest 24개, Chromium mock 3개, 실제 Chromium–FastAPI–Semgrep E2E 1개 통과였다. 우선 오프라인 Quick Start, 도움말, 상태 메시지, 기술 상세를 확인하는 테스트를 추가해 RED를 확인한 뒤 구현했다. 구현 후 새 테스트를 포함한 해당 프론트엔드 테스트 28개가 통과했다.

최종 검증 결과는 작업 종료 시 아래 표에 기록한다.

| 검증 | 결과 |
| --- | --- |
| `uv lock --check` | 통과 |
| `uv sync --locked --dev` | 통과 |
| `SEMGREP_REQUIRED=1 uv run python -m pytest -q` | 532 passed, 28 skipped, 0 failed; Starlette TestClient deprecation warning 1건 |
| Node.js 24.22.2 `npm ci` | 통과; audit 취약점 0건 |
| `npm run typecheck` | 통과 |
| `npm test` | 42 passed |
| `npm run build` | 통과 |
| `npm run test:browser` | Chromium mock 3 passed |
| `SEMGREP_REQUIRED=1 npm run test:e2e:real` | 실제 Chromium–FastAPI–Semgrep 1 passed |
| `git diff --check` | 통과 |

Vitest는 42개가 통과했다. Chromium mock 3개와 실제 FastAPI/Semgrep E2E 1개도 통과했다. 기존 브라우저 테스트는 기술 상세가 접혀 있는 새 구조에 맞춰 사용자 클릭 후 supported/restricted 근거를 검사하도록 조정했다. 별도의 axe 실행 명령은 `frontend/package.json`에 정의되어 있지 않으며, 이 Phase에서 axe 결과를 주장하지 않는다. 브라우저 검증에는 320px 넘침 여부와 키보드로 토큰 필드 및 지우기 버튼에 도달하는 확인이 포함된다.

## 사용자 검수와 남은 한계

자동 테스트는 문구와 동작을 검증할 뿐 사용자의 이해도를 증명하지 않는다. Phase 6J의 Q1–Q6는 모두 `NOT_TESTED`로 유지한다. Phase 6J의 실제 사용자 피드백은 개선 동기를 제공하지만, 이번 변경이 초보 사용자 전체에 효과가 있다고 일반화하지 않는다. 개선 UI를 사용자가 직접 확인한 뒤 별도 수용 검수를 재개해야 한다.

현재는 등록된 로컬 target만 선택할 수 있다. GitHub URL 분석과 임의 폴더 선택은 구현하지 않았다. 두 기능은 입력 검증, 저장소/경로 격리, 네트워크 및 파일시스템 보안 경계를 별도로 설계한 후속 Phase로 분리한다. 실제 사용자 프로젝트, Safari, VoiceOver, 실제 모바일 기기 및 모델 기반 분석은 이번 Phase에서 검증하지 않는다.

## 후속 권고

개선된 UI를 대상으로 Q1–Q6 사용자 검수를 다시 진행하고, 각 답변과 오해가 발생한 문구를 원문대로 기록한다. 추가 사용자 모집이나 운영 환경 검증이 이뤄지기 전에는 사용자 이해도·업무 생산성 향상을 주장하지 않는다.
