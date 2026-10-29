# Phase 6L — 초보 사용자 대시보드 직접 검수

## 시작 Gate

| 항목 | 관찰 결과 |
| --- | --- |
| 저장소 / remote | `misosos/ai-code-security-analyzer` / `https://github.com/misosos/ai-code-security-analyzer.git` |
| branch | `main` |
| 시작 HEAD / `origin/main` / 원격 `main` | `a8c7be5a6b900a862b6aea3e610a360f2c21d244` 일치 |
| 시작 작업 트리 | clean |
| 시작 ahead/behind | 0/0 |
| 기준 SHA | `a8c7be5a6b900a862b6aea3e610a360f2c21d244` 일치 |
| GitHub Actions | Run `40893259484`, 기준 SHA, `push / completed / success` |
| 필수 job | Python/CLI, Semgrep 1.182.1 integration, React dashboard 및 실제 Chromium–FastAPI–Semgrep E2E 모두 성공 |
| Actions artifacts | 0 |
| 로컬 런타임 | Python 3.12.7, Semgrep OSS 1.182.1; 빌드된 UI를 FastAPI에서 제공하므로 브라우저 실행에 Node 서버는 필요하지 않음 |

작업 시작 시 `8765`, `5173` 포트를 사용하는 서버가 없었다. 서버를 종료하거나 기존 설정을 바꾸지 않았다.

## 시연 환경

- 실제 UI: `http://127.0.0.1:8765/`에서 FastAPI가 제공하는 빌드된 React 화면
- 검사 API: 동일 출처의 `/api/v1` 경로
- 합성 대상: 각 검수 문항에 맞춰 기존 합성 fixture를 임시 프로젝트에 배치. 현재 Q6 확인용 대상은 안전한 상수만 내보내는 `hello.js` 한 파일
- 선택할 프로필: `Experimental Command Injection` (`command-injection-experimental`)
- Semgrep: OSS 1.182.1, 실제 로컬 규칙 및 실제 API 요청
- 네트워크: FastAPI는 `127.0.0.1:8765`에만 listen. 이 시연에서 실제 사용자 프로젝트나 외부 서비스는 사용하지 않음

임시 시연 디렉터리는 `/tmp/aicsa-phase6l-acceptance-171adab`이며 폴더 권한은 `0700`, 토큰 파일 권한은 `0600`이다. 토큰은 Python `secrets`로 무작위 생성했으며 값은 문서·로그·채팅에 기록하지 않았다. 사용자가 대시보드에 입력하려면 로컬 터미널에서 다음 명령으로 클립보드에 복사할 수 있다.

```sh
pbcopy < /tmp/aicsa-phase6l-acceptance-171adab/token.txt
```

이 파일은 시연이 끝난 뒤 제거한다. 토큰을 공유하거나 저장소에 추가하지 않는다.

### 실제 Semgrep 사전 확인

로컬 시연 API를 사용해 합성 프로젝트를 실제 검사했다. API가 반환한 안전한 메타데이터는 다음과 같다.

- 상태: `completed`, Finding 1건, 표시 1건, 생략 0건
- Rule ID: `experimental.javascript-command-injection-taint`
- 심각도: `high` (도구 분류)
- 위치: `route.js:3`
- Finding 상태: `unverified`
- Evidence 상태: `validated`

이 결과는 규칙 매치와 구조화된 근거가 반환됐다는 뜻이다. 취약점 확정이나 실제 외부 입력 도달성의 증거가 아니다. 검수용 Finding은 API에서 한 번 사전 확인한 것이며, 사용자는 대시보드에서 다시 검사해 화면 흐름을 확인할 수 있다.

Q5용 추가 시나리오로 기존 합성 `generic/job.js`를 같은 임시 프로젝트에 추가하고 `Experimental JavaScript Eval` 프로필을 실제 실행했다. 결과는 `completed`, Finding 2건이며 `experimental.javascript-eval-taint`와 `experimental.javascript-eval-taint-with-synthetic-sanitizer`가 `generic/job.js:3`에 각각 보고됐다. 두 결과는 모두 `unverified`; 실제 HTTP 요청 등록이나 런타임 입력 도달성을 확인한 것이 아니다. 이 시나리오는 코드 실행 없이 정적 분석만 수행했다.

Q6 확인을 위해 임시 합성 대상을 `hello.js` 한 파일로 교체하고 `Baseline Rules`로 실제 API 검사를 실행했다. 결과는 `completed`, Finding 0건, 표시 0건, 생략 0건, issue 없음이었고 Semgrep은 1.182.1이었다. 이 검사는 실제 Semgrep 결과다. 사용자는 대시보드에서 같은 대상을 다시 검사해 화면을 직접 확인해야 하며, 이 사전 API 확인은 사용자 응답이나 PASS가 아니다.

### 동일 출처 및 응답 확인

`GET /`는 HTTP 200의 빌드된 HTML을 반환했고 `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, 제한된 CSP가 포함됐다. `GET /api/v1/health`는 HTTP 200을 반환했다. 실제 listen 주소는 `127.0.0.1:8765`다.

## 사용자 검수 상태

Phase 6J Q1–Q6를 한 번에 하나씩 진행한다. 자동 테스트 및 실제 Semgrep 사전 확인은 사용자 검수 PASS가 아니다. PASS/NOT_TESTED 표기는 답변을 근거로 한 검수 기록자의 분류이며 사용자가 직접 쓴 말로 간주하지 않는다. 원문 응답은 아래 인용에 보존한다. 미응답 항목은 `NOT_TESTED`다.

| 문항 | 사용자 검수 질문 | 상태 | 최초 응답 / 피드백 |
| --- | --- | --- | --- |
| Q1 | 이 Finding은 취약점이 확정된 결과인가? | PASS | 최초 응답: “아니요.” 사용자가 직접 답변함 |
| Q2 | 실제 Source 위치와 Sink 인자 위치가 확인되었는가? | PASS | 최초 응답: “아니요. 실제 Source 위치와 Sink 인자 위치는 모두 확인되지 않았습니다.” 사용자가 직접 답변함 |
| Q3 | Trace가 없다는 것이 데이터 흐름이 없다는 뜻인가? | PASS | 최초 응답: “아니요.” 사용자가 직접 답변함 |
| Q4 | 이 Finding에서 코드 수준으로 확인해야 할 다음 작업은 무엇인가? | PASS | 입력 출처, 위험 함수 인자, 입력 검증, 실행 조건을 구체적으로 제시함. 원문은 아래 응답 기록 참조 |
| Q5 | 일반 객체가 Source 패턴에 매치됐을 때 실제 HTTP 입력이라고 결론 내릴 수 있는가? | PASS | 최초 응답: “아니요. 일반 객체가 Eval Source 패턴에 매치됐다는 사실만으로 실제 HTTP 요청 입력이라고 결론 내릴 수 없습니다.” 사용자가 직접 답변함 |
| Q6 | Finding이 0건이면 검사한 프로젝트가 안전하다고 판단할 수 있는가? | PASS | 최초 응답: “아니요.” 사용자가 직접 답변함. 실제 API 사전 검사에서 completed/0건을 확인했으며 이는 사용자 응답을 대체하지 않음 |

별도 사용성 항목(Quick Start, 토큰, 대상/프로필 구분, Finding 의미, Source/Sink/Trace 한계, 부분/0건 상태, 다음 작업 찾기)은 항목별 직접 평가 전까지 `NOT_TESTED`로 둔다. 아래 부분 검사 화면은 실제 결과와 분리된 고정 Mock이며, 사용자가 확인하고 답하기 전까지 평가는 `NOT_TESTED`다.

### 추가 사용성 응답

| 항목 | 상태 | 최초 응답 |
| --- | --- | --- |
| Quick Start로 서버 실행부터 검사 시작까지 파악 가능 | PASS | “네.” |
| API 토큰의 목적과 입력 방법 이해 | PASS | “네.” |
| 검사 대상과 규칙 프로필 구분 | PASS | “네.” |
| Finding과 취약점 확정의 차이 이해 | PASS | “네.” |
| Source/Sink/Trace의 한계 이해 | PASS | 최초 응답 원문은 아래에 기록 |
| 부분 검사 상태 이해 | PASS | Mock Q1~Q3에 사용자 응답을 받음. 응답 원문은 아래 기록 참조. 원인 코드 미제공 시 다음 행동 문구의 불일치도 관찰 |
| 완료·0건 결과의 의미 이해 | PASS | “네.” |
| 실제 결과에서 다음 검토 작업 찾기 | PASS | 사용자가 실제 검토 항목을 설명함. 응답 원문은 아래에 기록 |

### 사용자 응답 원문

**Q4:**

> 현재 발견된 route.js:3을 기준으로 다음 사항을 확인해야 해요.
> 1. 입력 출처: 사용자 입력인지, 외부 HTTP 요청인지, 내부에서 생성된 값인지 확인합니다.
> 2. 위험 함수의 인자: 입력값이 명령 실행 함수에 어떻게 전달되는지 확인합니다.
> 3. 입력 검증: 위험 함수에 전달되기 전에 입력값을 검증하거나 제한하는 로직이 있는지 확인합니다.
> 4. 실행 조건: 해당 코드가 실제 실행될 수 있는 경로인지 확인합니다.

**Q5:**

> 아니요. 일반 객체가 Eval Source 패턴에 매치됐다는 사실만으로 실제 HTTP 요청 입력이라고 결론 내릴 수 없습니다.

**Q6:**

> 아니요.

**추가 사용성 — Source/Sink/Trace:**

> 네, 이해할 수 있었습니다.
>
> Source·Sink 위치가 확인되지 않거나 Trace가 없다는 것은 분석 도구가 데이터 흐름을 검증할 충분한 근거를 제공하지 못했다는 의미입니다.
>
> 따라서 이 사실만으로 데이터 흐름이 존재한다고도, 존재하지 않는다고도 확정할 수 없습니다. 실제 데이터 흐름을 확인하려면 입력 출처부터 위험 함수까지의 코드 전달 과정과 실행 조건을 추가로 분석해야 합니다.

**추가 사용성 — 완료·0건 결과:**

> 네.

**추가 사용성 — 다음 검토 작업 찾기:**

> 네, 이해할 수 있었습니다.
>
> Source·Sink 위치가 확인되지 않거나 Trace가 없다는 것은 분석 도구가 데이터 흐름을 검증할 충분한 근거를 제공하지 못했다는 의미입니다.
>
> 따라서 이 사실만으로 데이터 흐름이 존재한다고도, 존재하지 않는다고도 확정할 수 없습니다. 실제 데이터 흐름을 확인하려면 입력 출처부터 위험 함수까지의 코드 전달 과정과 실행 조건을 추가로 분석해야 합니다.

### 부분 검사 상태용 고정 Mock

- 접속 주소: `http://127.0.0.1:8766/` (loopback 전용 임시 Mock 서버)
- 기존 React production 빌드를 사용하되, 이 주소의 `/api/v1`만 고정 응답을 반환한다. 실제 FastAPI/API·분석 엔진·규칙·검사 결과는 변경하지 않는다.
- 화면 상단 표시: `[검수용 Mock — 실제 Semgrep 검사 결과 아님]`. 함께 “이 Mock 응답에는 구체적인 원인 코드가 없습니다. 원인은 확인할 수 없으며 추정하지 않습니다.”를 표시한다.
- 기존 ScanResponse DTO 값: `scan_status=partial`, `completed=false`, `semgrep_version=null`, Finding/displayed/omitted 수 0, 모든 severity 수 0, `issues=[]`, `limitations=[scan_partial, scan_result_is_not_safety_proof]`, `findings=[]`.
- 임시 Mock에서만 토큰 필드에 `phase6l-mock-only`를 입력한다. 비밀값이나 실제 서버 토큰이 아니다. 임시 handler는 비어 있지 않은 토큰 헤더를 요구하고 고정 DTO만 반환한다.
- 준비 확인: Chromium에서 페이지를 열고 검사 버튼을 눌러 배너, 부분 검사 안내, 0 Finding 안내, 제한 도움말을 확인했다. JavaScript page error 0건. 이 자동 확인은 사용자 PASS가 아니다. 로컬 Node `26.9.0`으로 실행했으며 프로젝트 지정 `24.22.2` 검증 환경은 아니다.
- 캡처 파일: `/tmp/aicsa-phase6l-acceptance-171adab/partial-mock-screen.png` (저장소 밖, 커밋하지 않음).

Mock 화면을 확인한 후 다음 문항을 한 번에 하나씩 진행했다. 표의 상태는 사용자 원문 응답을 근거로 한 기록자 분류다.

| 문항 | 질문 | 상태 | 사용자 응답 |
| --- | --- | --- | --- |
| Mock Q1 | 이 화면에서 검사가 정상적으로 전부 완료됐다고 볼 수 있나요? | PASS | 최초 응답 “부분검사완료인데” 후 명확화: “아니 부분완료검사라고 보여”. 응답 원문 보존. 기록자의 해석: 화면의 부분 완료 상태를 인지함 |
| Mock Q2 | Finding이 0건이므로 프로젝트가 안전하다고 판단할 수 있나요? | PASS | 최초 응답: “아니” |
| Mock Q3 | 이 결과에서 어떤 부분을 추가로 확인해야 하나요? | PASS | 응답 원문은 아래에 기록 |

**Mock Q2:**

> 아니

**Mock Q1 최초 응답:**

> 부분검사완료인데

**Mock Q1 명확화 응답:**

> 아니 부분완료검사라고 보여

**Mock Q3:**

> 검사가 부분적으로만 완료되었으므로, 어떤 파일이나 검사 규칙이 누락되었는지 확인해야 합니다. 또한 부분 검사로 끝난 원인을 확인하고, 문제를 해결한 뒤 다시 검사해야 합니다. 현재 화면에서는 구체적인 원인을 알 수 없습니다.

### 검수 중 발견한 개선 후보

고정 Mock은 원인 코드를 제공하지 않았고 화면 상단에도 이를 명시했다. 그러나 기본 `scan_partial` 도움말의 다음 행동은 “함께 표시된 원인을 확인하고, 해결 후 다시 검사하세요.”라고 안내한다. 원인 코드가 응답에 없을 때는 이 문구가 실제 다음 행동을 충분히 안내하지 못할 수 있다. 사용자는 누락된 파일/규칙과 원인을 추가로 확인해야 하며, 현재 화면에서는 구체적 원인을 알 수 없다고 답했다. 이번 Phase에서는 UI를 수정하지 않는다. 후속 UX 작업에서 원인 코드가 있을 때와 없을 때의 안내를 구분하고, 원인이 없는 경우 추측 없이 분석 담당자나 서버 운영자에게 확인하도록 안내할 수 있다.

문제가 보고되면 기능 오류, 문구 이해 문제, 사용 절차, 정보 부족, 별도 기능 요청으로 분류하고 원래 응답을 보존한다. 이번 Phase에서는 검수 전 UI를 수정하지 않는다.

## 개인정보 및 결과 보관

검수에는 기존 합성 코드 사례를 순차 사용했고 실제 사용자 프로젝트는 사용하지 않았다. 코드 원문, 실제 API 토큰, Semgrep 원문 JSON 및 실제 사용자 절대 경로를 검수 문서에 복사하지 않았다. Mock 토큰은 비밀값이 아니며 Mock 요청에만 사용했다. 외부 업로드와 모델 호출은 하지 않았다. 두 임시 서버는 검수 후 종료했고 임시 토큰 파일, 합성 프로젝트 및 임시 server script를 제거했다. OS 수준 네트워크 차단을 검증했다고 주장하지 않는다.

## 검수 종료 및 후속 작업

핵심 Q1–Q6, 추가 사용성 문항 및 부분 검사 Mock Q1–Q3에 실제 사용자 응답을 받았다. 기록자의 응답 분류 기준으로 모두 PASS이며 사용자 원문은 별도 인용돼 있다. Phase 6L 사용자 검수 판정은 `PHASE_6L_USER_ACCEPTANCE_COMPLETE`다. 이는 한 명의 사용자가 합성 시연에서 답한 결과이며 다른 사용자 집단이나 실제 프로젝트에 일반화하지 않는다.

검수 완료 후 loopback 시연 서버와 Mock 서버를 종료했다. 임시 API 토큰 파일, 합성 프로젝트 및 임시 Mock server script를 제거했다. 캡처 이미지는 `/tmp/aicsa-phase6l-acceptance-171adab/partial-mock-screen.png`에 남아 있으며 저장소에 포함하지 않았다.

검수 이후에는 Phase 7A의 Secure Local Project Selection을 별도 설계한다. 로컬 폴더 선택/등록, 경로·symlink 방어, 검사 격리 및 네트워크 정책을 우선 검토한다. GitHub URL 자동 분석은 원격 다운로드와 비신뢰 저장소 처리를 위한 별도의 보안 설계 뒤로 미룬다.
