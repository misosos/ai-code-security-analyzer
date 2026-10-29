# Phase 6H — Eval Taint Source Provenance 및 Framework Context 검증

## 목적과 시작 Gate

기준 커밋은 `160bb64051022a48f123c74886d083a51508b2db`다. 저장소 remote는 `misosos/ai-code-security-analyzer`, 현재/원격 branch는 `main`, HEAD와 `origin/main`은 기준 SHA, 시작 worktree는 clean이었다. Semgrep OSS는 1.182.1이었다. 기준 GitHub Actions Run `40864164479`는 기준 SHA의 `push / completed / success`, artifact 0개였다. Python, Semgrep, Frontend, Chromium job이 모두 성공했다.

기준 파일 SHA-256:

| 대상 | SHA-256 |
| --- | --- |
| `rules/experimental/javascript-eval-taint.yml` | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| `rules/security-baseline.yml` | `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3` |
| `rules/experimental/javascript-command-injection-taint.yml` | `a06063859bb8ce2c284412a5922fa2674679b27fbcfb3a5e12625ad430a73fb8` |
| `rules/experimental/react-html-sink-coverage.yml` | `a2c70b591a8e7f37b9ad17a88636a9c5ef7259f0bcc6b5946a0893e5ff73cf36` |
| 신규 `rules/experimental/javascript-eval-source-context.yml` | `ad3d1515a63d434ceefdc29bc23a56f7d791607d33ad79df061c4ad8794773d1` |
| Phase 6E manifest | `0aa7c9ebf89f9f79ce737db7595cd2b795c989aa5f7de825f1a54d8e5e005c24` |
| Phase 6E Oracle | `b62dd1b912305d199a640493a2ad1fae00917b65cb87450cd74e561cbb2b54fb` |

## 기존 Source 모델

변경하지 않은 `experimental/javascript-eval-taint.yml`은 `$REQ.query.code`와 `$REQ.body.code`를 source, `eval($CODE)`를 sink로 정의한다. `$REQ`는 Semgrep metavariable이므로 특정 변수명이나 framework 타입으로 제한되지 않는다. 이 선언은 필드 구조에 대한 분석 모델이지 HTTP 입력임을 검증하는 선언이 아니다. 두 규칙은 각기 기본 taint와 `syntheticSafe(...)` sanitizer 모델을 사용한다.

Express 문서에서는 `app.get()`/`app.post()` 등의 route method가 handler callback을 등록하며 요청에 맞는 handler를 호출하는 구조를 설명한다. [Express Routing](https://expressjs.com/en/guide/routing/). 이번 코드 평가는 그와 유사한 코드 구조가 있다는 사실만 확인한다. 서버 시작, 실제 route mount, 네트워크 요청 또는 실행 시 도달성은 검증하지 않았다.

## 기존 Phase 6E 사례 재현

여섯 사례를 별도 임시 합성 디렉터리에 복사해 기존 eval-taint 규칙을 실제 Semgrep OSS 1.182.1로 실행했다. Scan은 `completed`, exit code 0, issues 0이었다.

| 사례 | 실제 관찰 | 해석 및 기존 Oracle 의미 |
| --- | --- | --- |
| `ETX01_route_preview` | 기본 규칙과 sanitizer 규칙 모두 line 3 Finding | 함수가 `preview(req)`로 이름 붙었지만 Express route 등록은 없다. 실제 route provenance는 `insufficient_context`. |
| `ETX03_generic_record` | 두 규칙 모두 line 1 Finding | `record.query.code`가 source 구문과 일치한 일반 객체다. 실제 외부 입력 증거는 아니다. Oracle은 `lower_priority`. |
| `ETX07_alternate_field` | Finding 없음 | `query.expression`은 선언된 `query.code` source가 아니다. 기존 Oracle은 review-worthy의 `unsupported_pattern`. |
| `ETX08_helper_boundary` | Finding 없음 | route 함수는 source 형태를 helper에 전달하지만 eval sink 및 helper 정의가 없다. 구현/도달성을 추정하지 않는다. |
| `ETX09_other_object` | 두 규칙 모두 line 1 Finding | `job.query.code`도 `$REQ.query.code`에 구조상 매치한다. Source는 `undetermined`. |
| `ETX10_cross_file` | Finding 없음 | 기존 case에는 호출 파일만 있고 imported helper 구현은 scan corpus에 포함되지 않았다. 이 사례만으로 helper 내부의 cross-file flow를 평가했다고 할 수 없다. |

기존 fixture, Oracle 및 Phase 6E 결과는 변경하지 않았다. Phase 6E Oracle에서 ETX01/ETX03/ETX09는 syntactic Rule Signal positive, ETX07/08/10은 out-of-scope로 유지된다.

## Phase 6H 신규 합성 집합

`tests/fixtures/eval_source_phase6h/`에 33개 사례를 작성했다. 코드는 정적 분석 입력으로만 사용했고 실행하지 않았다. 모든 취약점 확인은 `NOT_EVALUATED`다. 기존 Phase 6E 사례를 복사하지 않았다. 개발자/Oracle 작성자는 기존 규칙과 평가에 노출되어 있었고 독립 리뷰는 수행하지 않았다. 이 데이터는 개발 평가이며 held-out 또는 실제 저장소 성능 평가가 아니다.

Rule Signal, Source Context, Security Review Relevance는 독립 축이다. 특히 N11/N12는 문맥 hard negative이지만 기존 `$REQ` 구문 모델에서는 Rule Signal positive가 될 것으로 사전 정의했다.

| 축 | 사례 분포 |
| --- | --- |
| Rule Signal | positive 17, negative 10, out_of_scope 6 |
| Source Context 전체 | framework_context_observed 17, generic_object_context 6, insufficient_context 9, out_of_scope 1 |
| Rule Signal positive의 Source Context | framework_context_observed 9, generic_object_context 5, insufficient_context 3 |
| Rule Signal positive의 Relevance | review_worthy 8, lower_priority 2, undetermined 7 |

집합에는 Express ESM/CJS route, `req` 이외의 request parameter 이름, Router, 등록되지 않은 route 유사 함수, 일반 `record/job/config/input` 객체, sink 없는 코드, 상수 eval, 요청 필드와 무관한 eval, 다른 객체 property, 변수 shadowing, fake Express package, destructuring, helper 및 cross-file 구조, synthetic sanitizer 모델을 포함했다.

## 현재 규칙 실측

| 규칙 | 점수 집합 | TP | FP | FN | TN | Precision | Recall | FPR | OOS 매치 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `experimental.javascript-eval-taint` | P17 / N10 | 17 | 0 | 0 | 10 | 1.00 | 1.00 | 0.00 | 0 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | P16 / N11* | 16 | 0 | 0 | 11 | 1.00 | 1.00 | 0.00 | 0 |

`*` P15(`syntheticSafe(req.body.code)`)은 기본 규칙의 positive이지만, synthetic sanitizer 모델 규칙에서는 명시된 모델 가정에 따라 negative/suppressed로 점수화했다. 이것은 `syntheticSafe`가 실제 안전한 sanitizer라는 주장이 아니다. 두 규칙 각각의 Finding은 case-level 1건이고 중복은 0이다. 단일 스캔에서는 두 rule ID가 같은 eval sink 위치에 각각 Finding을 낼 수 있어 두 ID를 합친 전체 출력은 33건이다. 이는 같은 Rule Signal의 33개 고유 finding이라는 뜻이 아니다.

기존 두 규칙에서 보고된 17개 사례 중 Source Context는 framework 형태 9, 일반 객체 5, insufficient context 3이었다. 실제 HTTP input 도달성이 확인된 사례 수는 0이다. Generic 객체와 불확정 입력을 `undetermined` 또는 `lower_priority`로 분리했으며 Finding을 제거하거나 source 위치를 생성하지 않았다.

## 제한적 Express 문맥 실험

별도 규칙 `experimental.javascript-eval-source-context`를 추가했다. 이 규칙은 `import express from "express"`, `const app = express()`, `app.<method>(path, (request, response) => { ... })`와 같이 코드 안에서 관찰되는 Express route 형태 내부의 `query.code` 또는 `body.code`만 source로 모델링하고 `eval(...)`을 sink로 둔다. 변수명이 `req`인지에 의존하지 않으며 callback parameter와 Source metavariable를 연결한다. 이 정규화된 형태는 특정 ESM default import 및 app 초기화 형태로 제한된다.

| 실험 규칙 집합 | TP | FP | FN | TN | Precision | Recall | FPR | OOS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Express-context Positive 7 / hard Negative 8 | 7 | 0 | 0 | 8 | 1.00 | 1.00 | 0.00 | 18 |

실제 7건은 `P01`~`P04`, `P06`, `P07`, `P15`이며 모두 예상 위치에서 단일 Finding이다. N11의 안쪽 함수 parameter shadowing 및 N12의 `fake-express` package 형태는 매치되지 않았다. 일반 객체 4종은 이 규칙의 out-of-scope로 분리되어 TN으로 세지 않았다. CommonJS Express인 P05와 `express.Router()`인 P08도 실제 framework 문맥이 코드상 관찰되지만, 이 experiment의 명시된 ESM `express()` app 패턴에는 포함되지 않아 out-of-scope로 기록했다. 따라서 이 수치는 실무 일반화나 취약점 재현율이 아니다.

새 규칙 Finding 7건의 제한적 Relevance는 review-worthy 6, undetermined 1(P15)이다. 규칙은 `syntheticSafe` sanitizer 모델을 적용하지 않으므로 P15도 보고한다. 기존 sanitizer 모델 규칙의 의미와 다르며 실제 sanitization 판단이 아니다.

## Evidence 및 결과 의미

현재 신뢰된 eval 규칙 결과의 TaintEvidence는 기존 계약을 그대로 따른다. `source_location=None / unknown`, `sink_location=None / unknown`, `flow_trace_status=absent`이며 Finding의 match line은 Semgrep match 위치다. Flow trace를 생성하지 않았다. 새 source-context rule ID는 TaintEvidence 신뢰 allowlist에 등록하지 않았으므로 해당 실험 Finding은 신뢰된 TaintEvidence나 supported taint claims를 생성하지 않는다. Rule 실행 자체와 실제 provenance 검증은 구분된다.

모든 Finding은 `unverified`이고 confirmation은 없다. `framework_context_observed`는 소스에서 route 등록 형태를 관찰했다는 분류일 뿐, 실제 웹 요청·외부 공격자 제어·방어 조건 부재를 증명하지 않는다. 일반 객체에서의 기존 규칙 매치는 검토 우선순위가 낮거나 출처가 불확정일 수 있지만, 이 코드가 실제로 안전하다는 결론도 아니다.

## 재현, 변경 및 제한

필수 실행은 로컬 합성 fixture와 trusted local rules만 사용했다. Semgrep OSS 1.182.1 scan status는 모두 `completed`; 규칙 변경 전후의 대상 데이터 실행 오류나 partial scan은 없었다. 신규 실험은 Semgrep의 같은 함수 내 taint 분석을 사용하며 함수 간·파일 간 흐름을 구현하지 않는다.

- 기존 `javascript-eval-taint.yml`, baseline, command/React/Firestore 규칙과 TaintEvidence allowlist/hash는 수정하지 않았다.
- 새 규칙은 `rules/experimental/`에만 두고 기본 프로필에 추가하지 않았다.
- `$REQ` source 구조에 대한 generic object 매치는 기존 규칙의 명시된 구문 의미와 일치한다. 이를 false positive 취약점으로 재라벨하지 않았고, 실제 request 여부에 대한 provenance 공백으로 기록했다.
- Express-context 실험은 요청 수신 실행이나 실제 Express dependency를 요구하지 않는다. fake package, shadowing 외 모든 binding 변경·복잡한 alias를 배제한다고 보장하지 않는다.
- 실제 입력 도달성, route mount, 서버 시작, authentication/validation, sanitizer 효과, 취약점 유무, 실제 사용자 코드의 탐지 품질은 검증하지 않았다.
- Phase 6E 및 Phase 6H 데이터는 독립 실무 성능 평가가 아니다.

Phase 6E ETX01/03/09의 실제 `SemgrepAdapter` 재현은 완료됐으며 Phase 6H의 4개 전용 테스트는 기존·신규 규칙을 실제 Semgrep으로 각각 실행한다. 신규 규칙은 `semgrep --validate`에서 유효했다. `uv lock --check`, `uv sync --locked --dev`, `git diff --check`도 통과했다.

최종 로컬 회귀:

- Python 전체: `530 passed, 28 skipped, 0 failed` (경고 1건: Starlette TestClient의 anyio 별칭 deprecation)
- Phase 6H 집중 Semgrep 테스트: `4 passed`
- Frontend: TypeScript typecheck 통과, Vitest `24 passed`, production build 통과
- Chromium browser tests: `3 passed` (기존 mock/UI browser suite)
- CI의 필수 Semgrep job에 `tests/test_eval_taint_phase6h.py` 추가

이번 변경에 대한 원격 GitHub Actions 실행은 아직 없다. push는 수행하지 않았다. 기준점의 Run `40864164479` 성공과 이번 로컬 변경의 테스트 성공은 별개의 증거다.

## 후속 권고

1. 새 context rule은 현재 synthetic 범위에서 hard negative를 통과했지만, 별도 미사용 데이터와 실제 Express app/route 구성 corpus에서 재검증하기 전에는 baseline에 편입하지 않는다.
2. CommonJS import와 Router 등록을 추가할지 판단하려면 module binding과 registration 문맥 hard negative를 먼저 확대한다.
3. AST 문맥과 실제 runtime source provenance 사이의 간극을 유지하고, Evidence 계약의 위치·trace 제한을 완화하지 않는다.
4. generic object Finding을 자동 숨기지 않는다. 출처가 미확인인 상태를 사용자에게 전달하는 표현은 별도 UI/API 변경 승인 및 평가 대상이다.
