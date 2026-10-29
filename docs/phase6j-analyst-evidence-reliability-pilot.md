# Phase 6J — Trace-Free SAST Analyst Review Reliability Pilot

## 목표 및 판정 범위

기준 커밋은 `bca43ddc67539596382a727c5866fc96a63ddb81`이다. Phase 6I는 Semgrep OSS 1.182.1의 JSON/SARIF에서 검증 가능한 Source/Sink 좌표와 구조화 trace를 얻지 못했다. 이번 단계는 기존 Review View, Markdown exporter, React Finding 상세가 확인된 구조적 사실과 제한을 전달하는지 자동 검증하고 사용자 검수를 준비한다. 사람의 이해도 평가는 아직 수행하지 않았다.

실제 취약점 존재, 공격 성공, 운영 코드에서의 탐지 정확도는 평가 범위가 아니다. 검수용 코드는 전부 합성 자료이며 실행하지 않았다.

## 시작 Gate

| 확인 | 결과 |
| --- | --- |
| 저장소 / remote | `misosos/ai-code-security-analyzer` / `https://github.com/misosos/ai-code-security-analyzer.git` |
| branch | `main` |
| HEAD / `origin/main` / 원격 main | 모두 `bca43ddc67539596382a727c5866fc96a63ddb81` |
| 시작 working tree | clean |
| ahead / behind | 0 / 0 |
| Semgrep | OSS 1.182.1 |
| exact-SHA Actions | Run `40874194733`, `push / completed / success`, head SHA 일치 |
| Actions artifact | 0 |

Run의 Python tests and CLI, Semgrep 1.182.1 integration, React dashboard job이 모두 성공했다. Python regression, real local-rule integration, Phase 6A/6D/6E benchmark, TypeScript/Vitest/build, Chromium smoke 및 required real Chromium–FastAPI–Semgrep E2E 단계가 모두 성공했다.

규칙 및 기존 평가 기준선 SHA-256:

| 파일 | SHA-256 |
| --- | --- |
| `rules/security-baseline.yml` | `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3` |
| `rules/experimental/javascript-eval-taint.yml` | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| `rules/experimental/javascript-command-injection-taint.yml` | `a06063859bb8ce2c284412a5922fa2674679b27fbcfb3a5e12625ad430a73fb8` |
| `rules/experimental/react-html-sink-coverage.yml` | `a2c70b591a8e7f37b9ad17a88636a9c5ef7259f0bcc6b5946a0893e5ff73cf36` |
| Phase 6E manifest | `0aa7c9ebf89f9f79ce737db7595cd2b795c989aa5f7de825f1a54d8e5e005c24` |
| Phase 6E Oracle | `b62dd1b912305d199a640493a2ad1fae00917b65cb87450cd74e561cbb2b54fb` |
| Phase 6I report | `04a9dfcfaac83815b53e47efcca8ee8e3b85a647f1c1b889ce8a2b0055d77919` |

위 파일의 바이트는 작업 전과 검수 준비 완료 시 동일했다. Phase 6A~6I의 규칙, fixture, Oracle, 결과 또는 historical 기록은 변경하지 않았다.

## 재사용한 근거 및 검수 표면

- Gate는 신뢰된 규칙 선언, Semgrep 관찰, 위치·trace 주장을 별도 ClaimType으로 판정한다.
- Summary/Consumer는 지원되지 않거나 사용할 수 없는 주장을 제한 상태로 유지하며 소비 시 규칙 근거를 재검증한다.
- Python Review View와 CLI `review-md`는 같은 Gate/Consumer 기반 renderer를 사용한다.
- React Finding 상세와 UI Markdown exporter는 서버가 반환한 Claim DTO를 구분해 표시한다. 프론트엔드는 claim을 자체 승인하지 않는다.
- Phase 3C의 기존 의미 Oracle, 재현 화면 생성기, 참가자 질문지와 Phase 5C/6I 자료를 재사용했다. Phase 3C 역시 실제 참가자 평가를 완료하지 않았으므로 사용자 PASS를 가져오지 않았다.

## 고정 의미 정책

다음 표는 자동 테스트를 실행하기 전에 이번 검수 기준으로 고정했다. 자동 테스트는 이 의미를 전하는 문구·구조가 유지되는지 확인할 뿐, 모든 사용자가 같은 의미로 이해한다고 증명하지 않는다.

| 관찰/상태 | 허용되는 해석 | 금지되는 해석 |
| --- | --- | --- |
| Finding match | Semgrep이 해당 규칙의 매치를 보고함 | 매치 위치가 Source와 Sink 모두의 좌표를 증명함 |
| 신뢰된 Source/Sink 선언 | 현재 검증된 로컬 규칙에 패턴 선언이 있음 | 선언이 실제 코드의 Source/Sink 위치를 확인함 |
| Source/Sink location unknown | 현재 근거로 좌표를 확인하지 못함 | 해당 Source/Sink가 없다고 결론 냄 |
| trace absent | 구조화 trace를 제공받지 못함 | 흐름이 없거나 Finding이 오탐이라고 결론 냄 |
| Express 유사 구문 관찰 | 코드에 route/handler 유사 문법이 있음 | 런타임 HTTP 입력 도달성이 확정됨 |
| 일반 객체 Source 매치 | 선언된 필드 구조와 구문상 매치됨 | 객체가 실제 HTTP 요청이라고 단정함 |
| high severity | 도구 분류가 high임 | 실제 악용 가능성 또는 취약점이 확정됨 |
| `unverified` | 취약점·오탐 모두 추가 검토가 필요함 | 취약점이 확정됨 |
| completed + 0 Finding | 완료된 검사에서 Finding이 보고되지 않음 | 코드가 안전함 |
| unsupported/out-of-scope | 현재 규칙·근거 계약의 지원 범위 밖임 | 보안상 문제가 없다고 판정함 |
| Finding 생략 | 생략 항목 수만 알 수 있고 개별 상태는 확인 불가 | 생략 항목이 안전함 |

취약점 확인 상태는 전 사례 `NOT_EVALUATED`다.

## 합성 검수 사례와 자동 검증 매핑

새 production 규칙이나 공개 계약을 만들지 않았다. 아래 검수 장면은 신규 사용자 검수 Oracle이며, 기존 결정적 테스트와 사전 평가 fixture를 참조해 중복 테스트를 피했다.

| ID | 검수 장면 | 고정 기대 해석 | 기존 자동 근거 |
| --- | --- | --- | --- |
| J01 | 일반 객체 필드가 Eval Taint Source 패턴과 매치 | 필드 형태 매치일 뿐 HTTP 출처 불명 | 신규 `generic/job.js`; 실제 scan Review 재현 |
| J02 | Express route 유사 handler의 taint match | 코드 문맥 관찰; 실제 route mount·도달성은 미확인 | 신규 `framework/route.js`; 실제 scan Review 재현 |
| J03 | 신뢰된 Source/Sink 선언 및 Finding match 위치 있음 | 선언과 match는 확인되나 Source/Sink 좌표 미확인 | `test_fixed_taint_policy_oracle_covers_supported_and_prohibited_meanings` |
| J04 | taint Finding에 trace absent | trace 미제공; 흐름 부재를 뜻하지 않음 | Review/Markdown/React claim 테스트, Phase 6I |
| J05 | 상수 React HTML Sink | 문법적 Sink 후보; 입력 출처·런타임 맥락은 따로 확인 | `frontend/tests/App.test.tsx`, React baseline 의미 테스트 |
| J06 | React Sink의 HTML 출처 불확정 | 출처를 임의로 판단하지 않고 Finding 상태 유지 | React Finding 상세 테스트 |
| J07 | `spawn(shell:true)` 형태 | 지원된 실험 규칙의 매치만 관찰; 실제 실행 영향은 미확인 | Phase 6F 평가/통합 결과 |
| J08 | 기본 spawn 또는 `shell:false` 형태 | 해당 Command Injection 규칙의 지원 범위 밖; 안전 판정 아님 | Phase 6F 평가/통합 결과 |
| J09 | partial scan | 부분 상태와 제한을 표시; 전체 완료 주장 금지 | `test_partial_and_failed_scan_have_distinct_fixed_semantics` |
| J10 | completed, Finding 0건 | 0건 결과이며 안전 증명 아님 | `test_pattern_and_zero_finding_oracles_do_not_overstate_results`, Markdown zero test |
| J11 | 규칙 해시 불일치 | 검증 유형을 분류하지 않고 지원된 taint 근거를 만들지 않음 | `test_unclassified_and_sanitizer_claims_remain_restricted` |
| J12 | 여러 Finding 중 출력 제한으로 일부 생략 | 총계와 생략을 밝히며 개별 생략 상태 미확인 | `test_multiple_findings_and_output_omission_preserve_totals`, Frontend omitted test |

이 표는 사용자에게 정답을 유도하기 위한 답안지가 아니다. 질문은 아래 별도 목록으로 전달하며, 평가자는 사용자의 최초 응답과 설명을 그대로 기록한다.

## 실제 Semgrep Review 재현 자료

### 실제 Semgrep 통합 화면: `RE-6J-MIXED-SOURCE-01`

Phase 6J 전용 합성 입력 두 개를 임시 디렉터리에 복사한 뒤 Semgrep OSS 1.182.1과 기존 Eval Taint 규칙으로 검사하고, `SemgrepAdapter._scan_with_evidence` 및 기존 `render_review`를 연결했다. 재현기 `uv run python tests/phase6j_review_material.py` 실행 결과는 `completed`, Finding 4건, 진단 0건이었다. Express-style route와 일반 객체 각각에서 기본 Eval Taint 및 synthetic sanitizer 모델 규칙의 Finding 한 건씩이 보고됐다.

안전하게 표시된 핵심 항목:

- Rule ID: `experimental.javascript-eval-taint` 및 `experimental.javascript-eval-taint-with-synthetic-sanitizer`, 각 2건
- Finding 상태: 네 건 모두 `unverified`
- 심각도: 네 건 모두 도구 분류 `high`; 실제 악용 가능성 판정 아님
- 매치 위치: `framework/route.js:6` 및 `generic/job.js:3` (상대 경로; Source/Sink 인자 좌표라는 뜻 아님)
- 기본 규칙 두 건은 구조적으로 validated이며 신뢰 선언과 5개 제한적 supported claim을 표시
- 두 synthetic sanitizer 규칙 결과는 선언/해시 모델에 따른 것이며 실제 sanitizer의 안전성을 확인하지 않음
- 네 결과 모두 Source 위치·Sink 인자 위치 unknown, trace absent, 취약점 확정 미지원
- 분석가 다음 작업: 실제 입력 출처, 위험 함수 인자, 검증/정제 구현, 함수 경계, 런타임 도달 조건 확인

합성 원본 코드, Semgrep 메시지/raw JSON, 절대 경로는 보고서에 복사하지 않았다. 이 장면은 실제 Semgrep 프로세스를 거친 Review View 출력이지, 실제 사용자 코드 검토가 아니다.

실제 Semgrep 연결 Review View는 다음으로 재현할 수 있다.

```bash
uv run python tests/phase6j_review_material.py
```

각 synthetic source 파일은 저장소의 [generic object fixture](../tests/fixtures/review_semantics_phase6j/generic/job.js)와 [Express-style fixture](../tests/fixtures/review_semantics_phase6j/framework/route.js)에서 확인할 수 있다. 스크립트는 코드나 Semgrep 원문을 Review 출력에 넣지 않는다. React의 실제 browser/API/Semgrep 전체 경로는 `npm run test:e2e:real`로 검증했으며, 테스트 종료 후 서버와 임시 자료가 정리된다. 지속 실행 중인 production 서버나 화면 캡처는 제공하지 않았다. 사용자는 위 재현 명령으로 실제 Semgrep Review View를 직접 확인할 수 있다.

## 자동 의미 검증 결과

기존 테스트를 재사용했다. Phase 6J를 이유로 중복 테스트를 추가하지 않았다.

| 의미 정책 | 자동 검증 근거 |
| --- | --- |
| Source/Sink 위치와 match line 구분 | Review semantic Oracle 및 Python/Markdown/React 제한 claim 테스트 |
| trace absent ≠ 흐름 부재 | `flow_trace_absent` 설명 및 forbidden phrase Oracle |
| unsupported claim 승격 금지 | Gate/Consumer Review 테스트, React API parsing 및 detail 테스트 |
| Consumer 검증 실패 | Python Review/Markdown; React validated claims 없음 테스트 |
| Finding `unverified` | Python Review semantic test, API schema fixed status, frontend runtime schema |
| high severity ≠ confirmed | `test_severity_verification_and_finding_count_are_distinct`, React detail |
| completed + 0 ≠ 안전 | Python Review/Markdown, React empty-state 테스트 |
| partial/failed 및 생략 | Python Review/Markdown, React scan response 테스트 |
| Markdown 의미 보존 | CLI review-md와 React UI summary 전용 테스트 |
| code/message/canary 비노출 | Python semantic canary test, React DTO schema/detail/export 테스트, Phase 6I 실제 Semgrep privacy test |
| 화면 연결 실제 경로 | Phase 6I required Chromium–FastAPI–Semgrep E2E 및 이번 회귀 재실행 |

### CLI와 React 차이 관찰

실제 내부 `SemgrepAdapter` 경로에서 `trusted_rules_directory=repository/rules`로 주고 검증한 결과는 taint 근거를 validated로 분류했다. 공개 CLI를 `--rules rules/experimental/javascript-eval-taint.yml`로 직접 호출한 별도 재현에서는 CLI가 규칙 파일 부모 디렉터리를 trusted root로 삼아 선언 경로를 신뢰하지 못했고, 같은 Semgrep match가 `unclassified`/신뢰 선언 확인 불가로 표시됐다. 이 출력도 Source/Sink/trace/취약점 주장을 승격하지 않아 과장은 없었지만, 명시적인 CLI rule 경로 호출과 서버 profile 사이에서 검증 분류가 다를 수 있다.

Phase 6J 범위는 CLI/API 계약과 production 동작 변경을 금지하므로 이 구성 차이는 수정하지 않았다. 따라서 Review 문구의 의미 정책은 일관되지만, 위 직접 CLI 호출과 API의 `validated` 상태가 일치한다고 주장할 수 없다. 분석가가 직접 CLI를 사용해 위 eval 규칙을 지정할 때는 이 제한을 알려야 한다. 후속 Phase에서 trusted root 해석을 별도 수정·회귀 검증할 것을 권고한다.

## 사람 대상 검수 질문 및 상태

Q1부터 한 문항씩 진행한다. 사용자가 답하기 전에는 모든 문항을 `NOT_TESTED`로 둔다. 자동 테스트, Phase 3C 자료, 작성자의 예상 답변은 사용자 PASS로 기록하지 않는다.

| ID | 질문 | 상태 | 화면 자료 |
| --- | --- | --- | --- |
| Q1 | 이 Finding은 취약점이 확정된 결과인가? | NOT_TESTED | `RE-6J-MIXED-SOURCE-01` |
| Q2 | 실제 Source 위치와 Sink 인자 위치가 확인되었는가? | NOT_TESTED | `RE-6J-MIXED-SOURCE-01` |
| Q3 | Trace가 없다는 것이 데이터 흐름이 없다는 뜻인가? | NOT_TESTED | `RE-6J-MIXED-SOURCE-01` |
| Q4 | 이 Finding에서 코드 수준으로 확인해야 할 다음 작업은 무엇인가? | NOT_TESTED | `RE-6J-MIXED-SOURCE-01` |
| Q5 | 일반 객체가 Source 패턴에 매치됐을 때 실제 HTTP 입력이라고 결론 내릴 수 있는가? | NOT_TESTED | J01 / `generic/job.js` |
| Q6 | Finding이 0건이면 검사한 프로젝트가 안전하다고 판단할 수 있는가? | NOT_TESTED | 기존 zero Review 화면 |

응답이 오면 최초 응답, 오해가 생긴 구체 문구, 수정 제안, 수정·재검수 여부, 최종 응답을 분리 기록한다. FAIL을 삭제하거나 사용자 재검수 없이 PASS로 바꾸지 않는다. 진행자가 앞서 짧은 `PASS` 답변을 Q1의 실질 답변으로 잘못 해석했으나, 사용자가 Q1에 답하지 못했다고 정정했다. 따라서 Q1은 `NOT_TESTED`이며 해당 `PASS`는 사용자 수용 결과로 집계하지 않는다. Q2–Q6도 질문하지 않았고 `NOT_TESTED`다. 별도 사용성 관찰로, 사용자는 로컬 API 토큰·규칙 프로필·Finding·부분 검사·근거 검증 상태의 개념과 사용 방법을 이해하기 어렵다고 보고했다.

## 사람 평가 상태와 제한

- 자동 의미 테스트: 통과. 사람의 이해도에 대한 증거가 아니다.
- 실제 Semgrep 통합 화면: 합성 route fixture에서 재현됨.
- React 실제 E2E: browser/API/Semgrep 경로는 자동 통합으로 검증됨. 사용자가 화면을 보고 답한 것은 아니다.
- 실제 사용자·운영 프로젝트·실제 모델: 평가하지 않음.
- 사용자 Q1–Q6: 모두 `NOT_TESTED`. 앞서 기록한 Q1 `PASS`는 사용자 정정에 따라 무효화했으며 수용 결과로 집계하지 않는다.
- 사용성 관찰: 기본 용어와 사용 방법 이해가 어렵다는 사용자 보고. 검수는 일시 중단했고 UI 수정은 수행하지 않았다.
- 최종 상태: `PHASE_6J_ANALYST_REVIEW_ACCEPTANCE_PAUSED_PENDING`.

## 검증 기록

기준 Gate는 exact-SHA remote CI와 local status로 확인했다. 로컬 검수 준비 중 다음을 실행했다.

- `uv lock --check`: 통과
- `uv sync --locked --dev`: 통과
- `SEMGREP_REQUIRED=1 uv run python -m pytest -q`: `532 passed, 28 skipped, 0 failed`; Starlette TestClient의 anyio alias deprecation warning 1건
- `uv run --locked python tests/phase6j_review_material.py`: 실제 Semgrep 생성 4건을 확인하고 Finding 상태, 구조적 근거 검증, Source/Sink unknown, trace absent 및 원문 비노출을 점검
- `mise exec node@24.22.2 -- npm ci`: 통과, dependency 취약점 0건
- `mise exec node@24.22.2 -- npm run typecheck`: 통과
- `mise exec node@24.22.2 -- npm test`: `24 passed`
- `mise exec node@24.22.2 -- npm run build`: 통과
- `mise exec node@24.22.2 -- npm run test:browser`: Chromium mock `3 passed`
- `SEMGREP_REQUIRED=1 mise exec node@24.22.2 -- npm run test:e2e:real`: 실제 Chromium–FastAPI–Semgrep `1 passed`
- `git diff --check`: 통과

`uv run pytest -q` console entrypoint는 로컬 Python 환경의 설치된 `tests` 이름 패키지와 namespace 충돌로 collection error를 냈다. 저장소/설정 변경 없이 `uv run python -m pytest -q`로 전체 suite를 다시 실행해 통과했다. Node 기본 경로는 22.18.0이라 저장소 요구 버전이 아니었으며, 설치된 Node 24.22.2를 `mise exec`로 고정해 frontend 검증을 수행했다.

CI의 필수 Semgrep job에 `tests/phase6j_review_material.py` 실행 단계를 추가했다. 출력은 합성 파일의 상대 경로, Finding ID 및 고정 Review 문구만 포함한다. 기존 Finding·TaintEvidence·Gate·Consumer·API/CLI DTO·React 공개 계약, 규칙, 평가 파일 및 dependency/lockfile은 수정하지 않았다. 작업 후 로컬 commit 전 working tree와 ahead/behind를 다시 확인한다.

## 다음 행동

사용자 요청으로 수용 질문을 일시 중단했다. 사용자가 로컬 API 토큰, 규칙 프로필, Finding, 부분 검사, 근거 검증 상태의 개념과 사용 방법을 이해하기 어렵다고 보고했다. 후속 조사 결과와 개선안을 먼저 제시한 뒤, 사용자 지시 전에는 Q1부터 검수를 재개하지 않는다. 진행자가 실행한 loopback 서버는 종료했고, 합성 fixture 외 대상은 설정하지 않았다. 새 스크린샷은 만들지 않았고 외부 네트워크 호출도 수행하지 않았다.

## 초보 사용자 관점 사용성 조사 (검수 일시 중단 시점)

UI/문서 동작을 확인했으며 변경은 하지 않았다.

| 조사 질문 | 현재 관찰 | 초보 사용자 영향 | 개선안 후보 (미구현) |
| --- | --- | --- | --- |
| 최초 실행에서 해야 할 일을 알 수 있는가? | 대시보드는 API에서 `/health`와 `/options`를 받아야 시작 설정을 표시한다. 서버가 꺼져 있으면 “FastAPI 서버와 허용 Origin 설정을 확인”하라는 기술적 오류만 보인다. 서버 실행 자체에는 프로젝트 절대 경로, 토큰 환경 변수, 경우에 따라 정확한 Origin 설정이 필요하다. | UI를 열기 전 서버를 별도로 설정해야 하며, 오류 화면만으로 설치·실행 순서를 해결하기 어렵다. | 저장소 기준 Quick Start를 첫 단계부터 제공: 빌드 확인, 허용 프로젝트 등록, 서버 실행, 브라우저 열기, 토큰 입력. 서버 미연결 화면에는 문서 링크와 고정된 다음 단계 제공. |
| 토큰 목적과 설정 방법이 설명되는가? | 입력은 “로컬 API 토큰”, “서버 설정 토큰을 입력하세요”로 안내하고, 요청 헤더 전달과 브라우저 미저장을 설명한다. Phase 5A 문서에는 환경 변수 설정과 43자 이상 난수 토큰 정책이 있지만, UI에서는 토큰이 누가 생성하는 값인지, 왜 필요한지, 실행 시 어디서 설정하는지 설명하지 않는다. 문서 예제는 임의 placeholder를 쓰므로 사용자가 그대로 쓸 값을 제공하지 않는다. | 입력란이 요구하는 비밀값의 출처·역할을 모르면 검사를 시작할 수 없다. | “서버 실행 시 관리자가 설정한 로컬 인증 비밀값”처럼 목적을 평이하게 설명하고, 로컬 요청 승인 목적·발급/복사 위치·재시작 시 변경 여부를 Quick Start에서 설명. 비밀을 웹 UI에서 생성/저장하거나 로그에 남기지 않음. |
| 결과와 취약점 확정의 차이가 쉬운가? | 첫 화면과 결과 화면에 Finding은 검토 후보이고 취약점 확정이나 안전성 보증이 아니라는 문구가 있다. 상세에는 `unverified`, `evidence_validation_status`, “구조적 근거”, Source/Sink, trace, Sanitizer, Claim 코드가 함께 보인다. | 핵심 경고는 있으나 전문 용어가 많아 사용자가 전체 의미를 연결해야 한다. 사용자의 직접 보고로도 용어 이해가 어렵다는 점이 확인됐다. | 결과 상단에 한 문장 요약: “도구가 검토 후보를 찾았습니다. 실제 취약점인지는 아직 확인되지 않았습니다.” `unverified`/`validated`를 각각 쉬운 문장으로 풀고 전문 상세는 펼쳐보기로 제공. |
| 결과 화면에서 다음 행동을 알 수 있는가? | Finding 상세에 고정된 “분석가 추가 검토 항목”이 있지만 입력 출처·Sink 인자·정제·함수 경계·런타임 도달성 같은 전문 작업을 나열한다. 오류/부분 검사에서는 원인별 조치가 제공되지 않는다. | 다음 행동 목록이 존재해도 초보자에게는 어떤 파일을 왜 확인할지, 어디서 시작할지 충분히 안내하지 못할 수 있다. | 각 상태와 Finding 유형에 맞춰 짧고 구체적인 첫 검토 행동을 안내하고, 근거가 없는 경우 추정 대신 확인할 수 없는 이유를 표시. |
| 부분 검사 원인을 이해할 수 있는가? | 부분 상태 안내는 누락 가능성을 설명하지만, 응답의 `issues`·`limitations` 값은 현재 `code-chip`으로 코드 문자열 그대로 표시된다. 예: `semgrep_timeout`, `findings_omitted`, `scan_partial`. 일부 세부 원인은 개인정보 보호상 고정 코드만 제공되므로 원문 stderr로 보충할 수 없다. | 상태가 왜 발생했고 무엇을 다시 해야 하는지 화면만으로 알기 어렵다. | 각 고정 코드를 한국어 제목·설명·안전한 다음 행동으로 매핑. 예: 시간 초과라면 범위를 줄여 다시 검사; 생략이면 표시 상한 때문에 개별 상태를 모른다고 설명. 이유가 API에 없는 경우 “원인을 더 자세히 확인할 수 없음”으로 명시. |
| 전문 용어 도움말이 필요한가? | UI에 설명 문장은 있으나 Finding, taint, Source/Sink, trace, Claim, 근거 검증 등의 짧은 용어집/도움말이 없다. 일부 enum 값과 식별자는 그대로 보인다. | 사용자는 설명을 읽으면서 여러 새 용어를 동시에 해석해야 한다. | 문맥형 도움말 또는 짧은 용어집 추가: Finding=검토 후보, 규칙 프로필=검사 규칙 묶음, 근거 검증=Finding과 규칙 정보의 연결 확인, Source/Sink/trace 설명. 용어집은 취약점 확정이나 데이터 흐름을 과장하지 않도록 정의 고정. |

이 조사는 한 사용자가 보고한 이해 어려움과 현재 코드·문서 관찰에 근거한 형성적 분석이다. 표본이 한 명이며 사람 대상 작업 관찰이나 비교 실험을 수행하지 않았으므로 모든 초보 사용자에게 일반화하지 않는다. Phase 6J의 Q1–Q6은 모두 `NOT_TESTED`; 자동 테스트 통과를 사람의 이해도 PASS로 대체하지 않는다. UI/API/문서 구현 변경, 재검수 및 접근성 재평가는 이번 조사에서 수행하지 않았다.

## 후속 개선 제안 (별도 Phase)

우선순위는 이번 한 명의 사용자 피드백과 UI/문서 관찰에서 나온 가설이다. 아직 구현하거나 사용자에게 재검수하지 않았다.

1. **Quick Start 및 API 토큰 안내:** 서버 실행부터 브라우저 접속, 서버가 설정한 토큰을 확인·입력하는 단계까지 초보자용 순서와 목적을 설명한다.
2. **검사 대상 선택 절차:** 대상은 서버 관리자가 사전 허용해야 한다는 보안 모델을 쉽게 설명하고, 현재 허용된 `Local Project`가 무엇을 가리키는지 확인하는 안전한 설정 절차를 안내한다. 임의 경로 선택은 추가하지 않는다.
3. **쉬운 한국어 결과 설명과 용어 도움말:** Finding, 규칙 프로필, 근거 검증, Source/Sink/trace 등의 뜻과 “검토 후보”와 “취약점 확정”의 차이를 문맥에 맞게 설명한다.
4. **부분 검사 원인과 다음 행동:** 고정된 상태·제한 코드를 한국어 설명 및 가능한 다음 단계로 표시한다. 응답에 원인이 없는 경우 원인을 추정하지 않고 확인 불가로 표시한다.
5. **합성 검사로 사용자 검수 재개:** 위 안내를 마련한 뒤 합성 프로젝트를 실제로 검사한 결과를 사용자가 확인하도록 하고, Q1부터 한 문항씩 새로 진행한다. 사용자 응답 전까지 모든 문항은 `NOT_TESTED`다.

GitHub URL 분석과 임의 로컬 폴더 선택은 이번 개선에 포함하지 않는다. 각각 외부 네트워크 요청 및 URL 검증, 파일시스템 경계·symlink·대상 격리 검토가 필요한 별도 기능 제안이다.

이번 사용성 조사 후 자동 테스트 suite는 추가 실행하지 않았다. 문서 편집의 형식 검증으로 `git diff --check`만 수행했다. 기존 Phase의 자동 테스트 결과는 이번 사용성 조사나 사람 대상 이해도 PASS를 뜻하지 않는다.
