# Phase 5D — Browser Security Validation

## 범위 및 기준

이 검증은 Phase 5A–5C의 로컬 웹 MVP를 합성 프로젝트로 확인한다. 기준 커밋은 `cb2df0b7627a5a42fd19daae1fb689a86aa27f12`이며, 사람 대상 사용성 평가와 실제 사용자 저장소의 탐지 정확도 평가는 포함하지 않는다.

실제 브라우저 검증 명령:

```sh
SEMGREP_REQUIRED=1 npm run test:e2e:real
```

`frontend/scripts/run-real-semgrep-e2e.mjs`는 임시 디렉터리에 합성 대상과 고정된 로컬 규칙 사본을 만들고, 테스트 전용 난수 토큰으로 loopback API를 기동한다. 사전 빌드된 React UI를 FastAPI가 제공한다. Playwright의 실제 핵심 요청은 라우팅/모킹하지 않는다. Chromium에서 검사 요청을 보내 실제 Semgrep OSS 1.182.1이 실행되고, 응답된 Finding의 Gate/Summary/Consumer 결과를 확인한 다음 사용자가 버튼을 눌러 Markdown 파일을 받는다. 다운로드 후 스캔 요청 수가 한 번인지 확인해 내보내기가 재검사를 유발하지 않음을 검증한다. 서버 프로세스와 임시 파일은 테스트 종료 시 정리한다.

실패 응답이 브라우저 테스트 산출물에 남지 않도록 trace, screenshot, video를 비활성화했다. 일반 Playwright 스모크 테스트는 mock/기존 방식이며, 위 명령의 실제 Semgrep E2E와 구분한다.

## 경계 검증

API 단위 테스트는 인증 누락·오류·과도한 토큰, 중복 Host/Origin/token/content-type/content-length, 잘못된 Origin 포트, 잘못된 Content-Type/JSON, 추가 필드, 16 KiB 초과 요청, 허용된 preflight, 401/403/400/413 및 내부 500을 확인한다. 거부 입력이 ScanService를 호출하지 않는지도 확인한다. target symlink 교체와 설정 중첩은 기존 테스트에서 확인하며, scan lock은 동시 요청 및 예외 후 재실행으로 확인한다.

보안 헤더(`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, CSP)는 정상 API, preflight, 경계 middleware의 조기 거부, FastAPI 500, 정적 HTML/JS/CSS 응답에 적용된다. 발견된 결함은 일부 조기 응답과 내부 500에 기존 Starlette 미들웨어가 헤더를 적용하지 못한 것이었다. FastAPI 앱 바깥의 ASGI `SecurityHeadersMiddleware`로 모든 HTTP 응답에 같은 정책을 적용했다.

Vite 개발 구성은 loopback에서 제공되고 `/api` 프록시는 고정 백엔드 대상으로만 동작하며 토큰을 주입하지 않는다. 브라우저 E2E는 FastAPI 정적 제공 경로를 사용한다. Origin은 설정된 정확한 loopback origin만 허용하고 CORS 와일드카드 및 credentials는 사용하지 않는다.

## 실제 E2E 주장 범위

Chromium에서 Command Injection experimental 프로필을 사용해 실제 Finding ID와 rule ID, Semgrep 버전, `verification_status=unverified`, `evidence_validation_status=validated`, taint 분류, supported/restricted claim, Source/Sink/trace 제한, 그리고 UI 보고서 내용을 확인한다. 합성 코드의 canary와 테스트 토큰이 API 응답·화면·다운로드에 포함되지 않는지도 확인한다.

이 결과는 실제 프로젝트의 취약점 정확도를 뜻하지 않는다. `validated`는 구조적 근거 연결 검증이며 취약점 확정이 아니다. Source/Sink 위치와 trace가 없다는 것은 해당 흐름이 존재하지 않는다는 뜻이 아니다.

## 자원 및 파일 시스템 한계

기존 경계를 유지한다: 요청 본문 16 KiB, 응답 1 MiB, 표시 Finding 최대 50, 단일 동시 scan, Semgrep 60초 timeout, Semgrep 출력 2 MiB, target 사전 검사 5초/100,000 항목. target 삭제, symlink 교체, 사전 검사 시간 및 항목 한도 초과를 테스트해 adapter 실행 전에 거부함을 확인했다. scan lock은 adapter 예외 후에도 해제된다. 실제 Semgrep 전체 경로는 고정 버전으로 실행하고, 오류 주입은 Fake Adapter 단위 테스트와 분리한다.

경로 재검증과 symlink 검사는 허용 범위 이탈 위험을 줄이지만 OS sandbox가 아니다. 검사 직전 이후 공격자가 파일 시스템을 동시에 변경하는 TOCTOU 경쟁을 제거하지 않는다. 테스트는 외부 네트워크가 OS 수준으로 차단됐다고 보장하지 않는다. 운영은 loopback 전용, 신뢰할 수 있는 로컬 대상 및 관리자가 허용한 규칙으로 제한해야 한다.

브라우저 다운로드 파일의 저장 위치·권한·보존 기간은 브라우저와 OS가 결정한다. 보고서에는 상대 경로와 규칙 ID가 남을 수 있어 외부 공유 전에 직접 검토해야 한다.

## 평가 기록

- GitHub Actions 기준 SHA 검증: `cb2df0b7627a5a42fd19daae1fb689a86aa27f12`에서 Python, Semgrep, Frontend 작업 성공 ([run 40820576902](https://github.com/misosos/ai-code-security-analyzer/actions/runs/40820576902)).
- 이번 Phase 로컬 검증: `uv lock --check`, `uv sync --locked`, Python `439 passed, 28 skipped, 0 failed`; Semgrep OSS 1.182.1 필수 묶음 `13 passed, 0 skipped`; Node 24.22.2/npm 11.19.1 `npm ci`, typecheck, Vitest `24 passed`, production build, 기존 Chromium `3 passed`; 실제 Chromium–FastAPI–Semgrep E2E `1 passed`.
- 이번 변경분의 원격 GitHub Actions 결과는 push를 하지 않으므로 아직 실행되지 않았다. CI의 실제 브라우저 통합 단계는 필수로 추가했다. 시작 기준 커밋의 CI 성공을 변경분 CI 성공으로 간주하지 않는다.
- 실제 참가자 평가: `NOT_TESTED`.
- 실제 사용자 프로젝트의 분석 품질 평가: 수행하지 않음.
- Release Readiness: `CONDITIONAL_GO`. 신뢰된 로컬 대상, loopback 단독 사용, 명시적인 프로젝트·규칙 allowlist와 검토된 다운로드 파일로 제한한다. OS sandbox 부재, 잔여 TOCTOU, 실제 사용자 코드 검증 부재 때문에 공격자 제어 저장소나 다중 사용자/원격 서비스 용도로 승인하지 않는다.
