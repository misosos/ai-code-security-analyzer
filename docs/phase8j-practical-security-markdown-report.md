# Phase 8J — 실무형 보안 분석 Markdown 보고서

## 목적과 범위

UI의 `현재 검사 결과 내보내기`가 만드는 `ai-code-security-ui-review-summary.md`를 분석가가 후속 검토에 활용하기 쉬운 구조로 정리했다. 변경 대상은 프론트엔드 보고서 생성기뿐이다. 분석가 수동 검토 Markdown, 비교 Markdown, JSON 백업, API DTO, Semgrep 규칙, Python CLI의 `review-md` 계약은 변경하지 않았다.

기존 보고서는 Finding마다 제한 Claim과 reason code를 본문에 모두 반복해 기계 식별자가 실제 검토 안내보다 두드러졌다. UTC 수신 시각만 출력했고, `_`를 HTML entity로 바꾸어 규칙 ID와 reason code의 가독성도 떨어졌다.

## 새 보고서 구성

1. 검사 개요: 검사 대상·규칙 프로필 ID, Experimental 여부, Semgrep 버전, 상태, 브라우저 결과 수신 시각(KST 및 원본 UTC), 전체/표시/생략 수와 범위 경고
2. 결과 요약: 심각도별 수, 주요 규칙, 구조적 근거 연결 수, 미확인 판단
3. Finding별 보안 검토: 위치·규칙·도구 심각도·Finding 유형·검증 상태, 확인된 구조적 사실, 미확인 사항, 다음 검토 제안, 해석 한계
4. 공통 분석 한계
5. 기술 상세 부록: Finding별 원본 지원 Claim, 제한 Claim, 결정, reason code 및 validation error code

Finding은 ID 기준으로 정렬하되 동일 규칙의 각 Finding은 별도 섹션으로 유지한다. API의 원본 순서인 Claim과 각 reason code 순서는 Finding별로 보존한다. 본문은 사람이 읽는 표현을 사용하고, enum과 코드 식별자는 안전한 인라인 코드 직렬화로 읽기 쉽게 표시한다.

## Pattern과 Taint 표현

- `pattern` Finding은 패턴 매치가 보고된 사실과 근거 연결 상태를 먼저 설명한다. 여러 Source/Sink 및 trace 제한은 결정 의미별로 간단히 묶으며, 데이터 흐름 부재를 뜻하지 않는다는 점을 분명히 한다.
- `taint` Finding은 API에서 지원된 Claim만 구조적으로 확인된 사실로 표시한다. Source/Sink 규칙 선언은 실제 코드 위치에서 Source/Sink가 관찰됐다는 주장과 구분한다. Flow Trace나 Sanitizer 근거가 없으면 그 부재만 표현하고, 흐름 또는 방어가 없다고 추정하지 않는다.
- `unclassified` Finding은 Taint나 Pattern으로 추정하지 않고 일반 검토 안내를 사용한다.
- `unavailable`, `insufficient_evidence`, `ambiguous`, `unsupported_claim`은 서로 다른 표현을 유지한다. Sanitizer 관련 제한도 Source–Sink 흐름 제한과 합치지 않는다. `unavailable`을 `not_applicable`로 바꾸지 않는다.

지원된 Claim과 제한 Claim의 API 값은 변경하지 않는다. `validated`는 매치와 근거의 구조적 연결 검증으로만 설명하며, 취약점 확정으로 표현하지 않는다. `unverified`는 미검증으로 그대로 보존한다.

## 실무 검토 제안의 근거

알려진 규칙에 대한 제한된 안내는 저장소의 고정 baseline 규칙과 설명을 확인해 작성했다.

- `baseline.javascript-dynamic-eval`: [security-baseline.yml](../rules/security-baseline.yml)의 `eval(...)`, `new Function(...)` 패턴과 [rules/README.md](../rules/README.md)의 입력 출처·대안 검토 범위를 반영한다.
- `baseline.react-dangerous-html`: 규칙의 `dangerouslySetInnerHTML` 매치와 README의 HTML 출처·정제 검토 범위를 반영한다.
- `baseline.firestore-unconditional-write`: 규칙의 리터럴 `true` 쓰기 권한 패턴에 따라 상위·중첩 match 범위, 인증·소유권 조건, 배포 상태 확인을 제안한다.

이 제안은 확인해야 할 작업이지 완료된 분석이 아니다. 보고서는 코드 원문이나 런타임 값을 포함하지 않으며, 규칙에 매치된 코드의 입력 도달성·방어 효과·실제 악용 여부를 확인했다고 주장하지 않는다. 알려지지 않은 Rule ID는 사용자 입력으로 규칙 이름을 만들지 않고 고정된 일반 검토 안내를 사용한다.

## 합성 보고서 전후 비교

기준 커밋의 실제 생성기와 새 생성기를 같은 합성 API 응답(일반 패턴 동적 코드 실행 Finding 1개, 제한 Claim 9개)으로 호출해 보고서를 만들었다. 생성 파일은 `/tmp/ai-csa-phase8j-before.md`와 `/tmp/ai-csa-phase8j-after.md`에 두었으며 저장소에는 포함하지 않았다.

| 측정 | 기존 보고서 | 개선 보고서 |
| --- | ---: | ---: |
| UTF-8 크기 | 4,128 bytes | 6,834 bytes |
| 본문에서 반복된 `taint_evidence_unavailable` | 3회 | 0회 |
| 기술 부록의 같은 원본 reason code | 지원 Claim별 본문과 함께 출력 | 3회, 원본 항목 각각에 보존 |
| 제한 Claim 본문 행 | 9개 기술 항목을 열거 | 의미가 다른 데이터 흐름, Sanitizer, 취약점 확정 제한을 읽을 수 있는 문장으로 구분 |
| KST와 UTC 수신 시각 | UTC 원문만 표시 | `2026-11-02 20:38:46 KST` 및 `2026-11-02T11:38:46.266Z` |

새 문서가 더 큰 이유는 기존 Claim·Decision·Reason Code 전체를 기술 부록에 보존하고, 구체적인 다음 검토 절차 및 시간대 설명을 추가했기 때문이다. 크기 증가는 정보 제거로 줄이지 않았다. 실제 화면 Markdown 렌더러에서의 시각 검수는 이 CLI/자동 생성 비교에 포함되지 않는다.

## 시간과 Markdown 보안

결과 수신 시각은 `Asia/Seoul`을 명시해 KST로 변환하고 원본 UTC ISO 시각도 함께 표시한다. 기본 로컬 시간대에 의존하지 않는다. 잘못된 수신 시각은 `scan_context_invalid`로 거부하며 현재 시각으로 대체하지 않는다. 이 값은 브라우저가 응답을 받은 때이며 실제 검사 실행 시각, 파일 수정 시각 또는 코드 스냅샷 시각이 아니다.

본문 텍스트는 기존 Markdown/HTML 특수문자 이스케이프를 유지한다. 경로, ID, Rule ID, enum 및 reason code는 동적 backtick 구분자를 쓰는 인라인 코드 직렬화로 표시해 `_`를 읽을 수 있게 하고 backtick 충돌은 처리한다. Unicode 제어·방향 제어문자는 가시적인 이스케이프 문자로 출력한다. API의 엄격한 `parseScan()` 검증을 보고서 생성 경계에서 다시 실행하고 절대 경로나 추가 토큰/코드 필드를 거부한다.

토큰, 코드 원문, 절대 경로, 원시 HTTP 데이터, stderr 및 임의 필드는 출력하지 않는다. 보고서는 UTF-8 512 KiB 제한을 유지하며 초과 시 전체 생성을 거부한다. 사용자 클릭에 의한 브라우저 다운로드만 수행한다. 서버 전송 또는 영구 저장은 없다.

## 변경 파일

- `frontend/src/features/scans/markdownExport.ts`
- `frontend/tests/markdown-export.test.ts`
- `frontend/tests/App.test.tsx`
- `frontend/browser-tests/dashboard.spec.ts`
- `frontend/browser-tests/real-semgrep.spec.ts`
- `docs/phase8j-practical-security-markdown-report.md`

## 검증 결과

환경: macOS arm64, Node.js `v24.22.2`, Python `3.12.7` (`uv`), uv `0.11.26`, Semgrep `1.182.1`.

| 검증 | 명령 | 결과 |
| --- | --- | --- |
| TypeScript | `mise exec node@24 -- npm run typecheck` (`frontend/`) | PASS |
| Vitest 전체 | `mise exec node@24 -- npm test -- --reporter=dot` (`frontend/`) | 115 passed, 11 files |
| Production build | `mise exec node@24 -- npm run build` (`frontend/`) | PASS |
| Chromium 전체 및 axe | `BROWSER_TEST_PREVIEW_PORT=41832 CI=1 mise exec node@24 -- npm run test:browser` | 46 passed, 41.8s; 7 axe 화면 상태 포함 |
| WebKit | `BROWSER_TEST_PREVIEW_PORT=41833 CI=1 mise exec node@24 -- npm run test:browser:webkit` | 2 passed |
| Safari QA 회귀 | `mise exec node@24 -- npm run test:qa:safari` (`frontend/`) | 7 passed, 40.9s |
| FastAPI–Semgrep–Chromium E2E | `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24 -- npm run test:e2e:real` (`frontend/`) | 2 passed, 26.6s |
| Python 전체 | `uv lock --check && uv run --locked python --version && uv run --locked python -m pytest -q -rs` | 542 passed, 28 skipped, 1 dependency deprecation warning; 222.32s |
| Semgrep 통합 | CI의 Semgrep 통합 테스트 파일 12개를 `SEMGREP_REQUIRED=1` 및 metrics/version-check 비활성화로 실행 | 44 passed, 1 dependency deprecation warning; 170.36s |
| whitespace 검사 | `git diff --check` | PASS |

첫 Chromium 시도는 기본 포트 4173의 기존 preview 서버 재사용으로 다른 UI가 열려 11개가 실패했다(35 passed). 제품 결함이 아닌 테스트 서버 출처 혼선으로 판단해 서버를 종료하지 않고, 고유 포트와 `CI=1`로 격리 재실행했다. 첫 격리 실행 및 최종 변경 상태의 재실행은 각각 46/46 통과했다. 최종 보고의 Chromium 결과는 최종 격리 재실행 결과다.

Linux Chromium은 이 로컬 macOS 환경에서 재현하지 않아 `NOT_VERIFIED`다. 새 커밋의 원격 Linux CI는 Push 뒤 별도로 확인해야 한다. 실제 macOS Safari 수동 검수, VoiceOver, 실제 Safari 200% 확대는 이 보고서 작업에서 하지 않았다.

## 한계

보고서의 다음 검토 항목은 규칙과 API가 제공한 구조적 근거에 기반한 고정된 권고다. 실제 코드, 입력 흐름, 실행 경로, 배포 환경 또는 방어 효과를 검사해 만들어진 분석 결과가 아니다. 정적 탐지 0건도 안전성 증명이 아니다. 사용자 검수 상태는 `SAFARI_USER_ACCEPTANCE_PENDING`이다.
