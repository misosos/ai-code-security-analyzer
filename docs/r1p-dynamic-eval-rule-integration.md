# R1-P — `baseline.javascript-dynamic-eval` 규칙 품질 수정

## 결정과 근거

R1 연구 커밋 `ff88612112a62a524f13464a9a163be5469e0f96`(브랜치 `research/r1-detection-capability`)에서 동결한 실험 규칙의 탐지 논리만 운영 규칙에 반영한다. 연구 브랜치 전체를 병합하거나 cherry-pick하지 않았다. 규칙 ID, 메시지, 심각도, CWE metadata, 언어, rule profile과 공개 API schema는 바꾸지 않았다.

| 항목 | 이전 | 이후 |
| --- | --- | --- |
| 탐지 구문 | `eval(...)`, `new Function(...)` | 이전 구문 + `($X, eval)(...)`, `Function(...)` |
| 별칭 | 없음 | `options.symbolic_propagation: true`로 단일 할당 별칭을 따른다. 이후 재할당하면 전파가 멈춘다. |
| 지역 바인딩 제외 | 없음 | `eval`/`Function` 매개변수, `const eval`, `let eval` (`function eval` 선언 제외는 R1-P-R1에서 제거) |
| 규칙 파일 SHA-256 | `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3` | `77d085dd4901863f8873c987f70d6ccd376ab33590724a1389885df09d5ff9df` |

현재 탐지 논리는 R1 동결 규칙(`experiments/r1-detection/rules/revised.yml`)에서 `function eval` 선언 제외 한 항목을 뺀 것과 같다(주석 제외). 규칙 바이트가 바뀌었으므로 Rule Bytes Identity 비교는 이 변경 전후 Run을 `DIFFERENT_SELECTED_BYTES`로 표시하는 것이 기대 동작이다.

## R1-P-R1 — 중첩 범위 미탐 수리

R1-P 커밋 `3c94687`의 push 전 감사에서 유효한 탐지 손실을 확인했다. `function f(code) { function helper() { function eval(v) { return v; } } return eval(code); }`에서 바깥 `eval(code)`는 실제 전역 eval인데, `function $F(...) { ... function eval(...) { ... } ... }` 제외가 Semgrep `...`의 중첩 범위 매치 때문에 이 호출까지 숨겼다. 이전 운영 규칙(`9dffe82`)은 이 호출을 탐지했다.

수리는 해당 제외 한 항목을 삭제하는 것으로 한정했다. 범위 분석을 새로 흉내 내는 복잡한 패턴은 추가하지 않았다. 대가로 같은 함수 안의 `function eval` 선언 shadowing 오탐이 되돌아왔고 알려진 한계로 기록한다.

합성 범위 probe(sloppy script, 양성 8 / 음성 10 / 모호 1)에서 확인한 결과:

| 규칙 | 양성(전역 호출) | 음성(지역 바인딩) | 비고 |
| --- | --- | --- | --- |
| A 이전 운영 `9dffe82` | 6/8 TP | 1/10 TN | 별칭·`Function()` 미탐, shadowing 오탐 |
| B R1-P `3c94687` | 7/8 TP (중첩 helper `function eval` 미탐) | 8/10 TN | 탐지 손실 |
| C 수리 | 8/8 TP | 7/10 TN | 남은 오탐: 같은 함수 `function eval`, `var eval`, 화살표 함수 매개변수 `eval` |

매개변수·`const`·`let`·`Function` 매개변수 제외는 바깥 범위 전역 호출을 숨기지 않았고, 바깥 지역 바인딩을 중첩 함수에서 사용하는 경우는 계속 제외했다. 블록 안 `function eval` 선언(Annex B)은 sloppy script에서는 함수 범위 지역 바인딩, strict 코드에서는 전역 eval로 해석이 갈리므로 양성·음성 어느 쪽으로도 고정하지 않았다(규칙은 이전 운영 규칙처럼 매치한다). 이 사례들은 native rule test(`ruleid`/`ok`/`todook`)에 반영했다.

## 근거로 인정한 범위

R1 동결 평가(라벨은 JavaScript 의미 기준, 규칙 수정 전 고정)의 held-out 18개 범위 내 지점에서 이전 규칙은 TP 3 / FP 2 / FN 9 / TN 4, 새 규칙은 TP 7 / FP 1 / FN 5 / TN 5였다. 운영 규칙으로 R1 scorer를 다시 실행한 결과는 R1 동결 결과와 지점별로 같았고, 이전 규칙 대비 사라진 TP와 새 FP는 dev·held-out 모두 0건이었다.

- held-out으로 확인: `Function(...)`(new 없음), Function 별칭 `new`, comma 간접 eval, `Function` 매개변수 shadowing 제외, 바깥 범위 전역 호출을 과도하게 제외하지 않음.
- dev 사례로만 확인: eval 별칭(단일 할당·체인·조건 분기·함수 경계 상수), `eval` 매개변수·블록 `const` shadowing 제외.
- R1-P-R1 수리 규칙의 새 측정(과거 R1 결과는 수정하지 않음): dev TP 22 / FP 2 / FN 1 / TN 16(41개 지점, `function_shadow.js`만 TN→FP), held-out TP 7 / FP 1 / FN 5 / TN 5(18개 지점, 변화 없음). 이전 운영 규칙 대비 사라진 TP와 새 FP는 0건이다.
- Semgrep Community Edition 규칙보다 우월하다는 주장은 하지 않는다. 비교 가능한 직접 eval 범주에서는 `eval-detected`와 같은 결과였다. 독립 엔진(IND-1C HOLD)이나 AI 기능과 무관하다.

## 알려진 한계

`tests/fixtures/dynamic_eval_rule_test/dynamic-eval.js`에 Semgrep `todoruleid`/`todook` 주석으로 남겨 숨기지 않는다. Semgrep은 `todo` 주석 줄을 검사하지 않으므로 이 주석은 한계의 기록이며 강제 테스트는 아니다.

- 오탐: 같은 함수 안의 `function eval` 선언, `var eval` 지역 바인딩, 화살표 함수 매개변수 `eval`, escape된 식별자 `\u0065val` 매개변수. 모두 sloppy script에서만 가능한 구문이며 ES module(strict)에서는 문법 오류다.
- 모호: 블록 안 `function eval` 선언(Annex B)은 실행 모드에 따라 의미가 달라 라벨을 고정하지 않는다.
- 미탐: `globalThis.eval`/`window.eval`, `globalThis.Function`, 구조 분해 별칭, `Reflect.construct(Function, ...)`, closure 안의 쓰기로 전파가 중단되는 별칭, 함수 간 래퍼, 내장 eval을 담은 `const eval` 지역 바인딩(A8, 아래).
- 범위 밖: 문자열 timer, Node `vm` API. 구문 탐지는 입력 출처·도달성·악용 가능성을 판정하지 않는다.
- 미해결 관찰: R1-C에서 taint 규칙(`detect-eval-with-expression`) 단독 실행 시 문법 오류 파일이 오류 없이 scanned로 보고됐다. 같은 파일은 이 규칙을 포함한 구문 규칙 실행에서 Semgrep 오류로 보고됐다. 원인(사전 필터로 파싱 생략 가능성)은 검증하지 않았으며, "scanned + 오류 0"을 파일 분석 완료로 해석하지 않는다.

### A8 — 내장 eval을 담은 `const eval` 바인딩 미탐 (검증됨, 미수정)

```js
function run(code) {
  const eval = globalThis.eval;
  eval(code);
}
```

- 전제: classic sloppy script(strict·ES module에서는 `eval` 바인딩이 문법 오류), `globalThis.eval`이 원래 내장 `%eval%`이고 사전 재할당이 없음.
- 기대: `eval(code)`에 Finding 1건. ECMA-262상 호출 대상은 `%eval%`이고, 참조 이름이 `eval`이며 값이 `%eval%`이므로 `run` 범위에서 실행되는 direct eval이다.
- 관찰(main `0053d21`, 규칙 SHA-256 `77d085dd…`, Semgrep OSS 1.182.1, 합성 파일 1개): 운영 규칙 Finding 0건, Semgrep 오류 0건. 임시 복사본에서 `const eval = $V; ...` 제외 한 항목만 지운 진단 규칙은 `eval(code)` 줄에 1건을 보고했다.
- 원인: `pattern-not-inside: const eval = $V; ...` 제외가 `$V` 값을 보지 않고 뒤따르는 모든 `eval(...)`을 지역 바인딩으로 간주한다.
- 보안 의미: 동적 코드 실행 검토 신호가 누락된다. 입력 출처·도달성·악용 가능성은 확인하지 않았다. sloppy 코드 한정이고 부자연스러운 형태이며, 더 단순한 `globalThis.eval(code)`도 이미 미탐이므로 영향은 낮게 본다.
- 미검증: 같은 구조의 `let eval = globalThis.eval`, 내장 eval을 인자로 받는 `eval` 매개변수 변형은 재현하지 않았다. `var eval` 형태는 운영 규칙에 해당 제외가 없어 탐지된다(SA-1 관찰). 실제 코드에서의 빈도는 측정하지 않았다. 의미 라벨은 독립된 사람 검토를 거치지 않았다.
- 기록: fixture의 `constBindingHoldsBuiltinEval`에 `todoruleid`로 남겼다. Semgrep `--test`는 `todo` 주석을 검사하지 않으므로 통과하는 회귀 테스트가 아니며 한계의 기록일 뿐이다.
- 향후 수정 수용 기준: (1) 이 재현을 `ruleid`로 승격하고 `let` 변형을 확인하면 함께 추가, (2) `const eval = JSON.parse` 등 기존 `ok` 주석이 모두 유지되거나 변경이 명시적으로 문서화됨, (3) `0053d21` 대비 R1 dev·held-out, R1-P-R1 probe, A1 DET, SA-1 사례에서 사라진 TP 0건, (4) 6A/6D/6E 결과 불변 또는 차이 문서화, 성능 변화 ±20% 이내, 전체 테스트 통과. 충족하지 못하면 규칙을 바꾸지 않고 한계로 유지한다.

### 종료된 연구 트랙 — SA-0 / SA-1

- SA-0(범위 분석 타당성): 확인된 범위 오류는 sloppy script 한정 shadowing 오탐이었고, 독립 이름 해석기가 Semgrep 규칙보다 단순하게 해결한다는 근거가 없어 PIVOT으로 종료했다. IND-1C는 HOLD로 유지한다.
- SA-1(제외 안전성 probe, 합성 사례, 일회성): `var eval` 제외는 오탐 5건을 줄였으나 내장 eval을 담은 `var eval` 1건을 놓쳤고, `catch (eval)` 제외는 오탐 3건을 줄였으나 `try` 블록 안 전역 호출과 내장 eval을 받은 catch 매개변수 2건을 놓쳐 둘 다 UNSAFE로 판정했다. 각 사례당 한 가지 패턴만 시험했으므로 Semgrep 엔진 한계로 일반화하지 않는다. A8은 이 probe에서 발견됐다.
- 두 트랙은 종료됐다. 실제 사용자 오탐 빈도 같은 별도 제품 근거 없이 재개하지 않는다.

## 벤치마크 영향과 Oracle

기존 corpus, Oracle, 과거 결과 파일은 수정하지 않았다.

- Phase 6A: 탐지 결과 동일. 보고서의 규칙 파일 SHA-256만 바뀐다.
- Phase 6D: 점수 지표는 동일하다. `EJ08_alias_wrapper`(모듈 상수 `eval` 별칭 호출)가 새로 매치되어 `out_of_scope_matches` 1건으로 보고된다. Oracle은 이 사례를 `out_of_scope`/`review_worthy`로 라벨했고 근거는 "현재 패턴이 직접 호출 규칙"이라는 이전 규칙 범위였다. 의미상 실제 eval 별칭 호출이므로 오탐이 아니라 확장된 범위의 매치다. 점수화되지 않으며 Oracle은 재라벨하지 않았다.
- Phase 6E: 사전 등록 해시가 이전 규칙 바이트에 고정돼 있다. 명령 주입 규칙의 선례와 같이 원본 바이트를 `tests/benchmark/phase6e/pinned_rules/security-baseline.yml`(SHA-256 `bfeb93c4…`)로 고정했다. 평가기 출력은 변경 전과 바이트 단위로 같았다.

## Finding ID 호환성

Finding ID는 `[rule_id, path, line, column, end_line, end_column]`에서 계산한다. 6A/6D/6E eval 사례, baseline fixture, R1 dev·held-out을 함께 검사했을 때 이전 규칙의 매치 42건 중 39건은 위치가 같아 ID가 유지됐다. 사라진 3건은 모두 지역 바인딩으로 라벨된 음성 사례(R1 `block_shadow` 안쪽, `parameter_shadow`, `H13`)였다. 새 매치 16건은 모두 양성 라벨 또는 6D `EJ08` 별칭이다. (R1-P `3c94687`에서는 `function_shadow`까지 4건이 사라졌다.)

## 검증

- Python 전체(수리 후): `681 passed, 28 skipped`(skip은 opt-in Ollama 전용), `SEMGREP_REQUIRED=1`.
- Semgrep native rule test(`semgrep --test`, 수리 후 fixture): 수리 규칙 통과. R1-P 규칙은 중첩 helper 사례(missed 1)로, 이전 운영 규칙은 missed 6 / incorrect 6으로 실패한다(테스트가 세 규칙을 구분함).
- 성능: 이 저장소 스냅샷(1,060 파일, JS/TS 392개)에서 규칙 순서를 번갈아 5 round × (cold 1 + warm 3) 측정. R1-P 규칙: 기본 ignore 적용 시 중앙값 비율(새/이전) cold 0.981, warm 1.009, 모든 파일 포함 시 cold 1.009, warm 1.001. 수리 규칙(모든 파일 포함): cold 0.937, warm 0.924. 수리 측정 시작 시 시스템 부하(load 11.6)가 높아 절대 시간은 흔들렸으나 교대 측정이라 비율은 비교 가능하다. cold는 새 HOME으로 Semgrep cache만 비운 것이며 OS page cache는 비우지 않았다. timeout·크기 상한은 바꾸지 않았다.
- 미검증: ER-D9 하네스는 외부 EJS 커밋 다운로드가 필요해 실행하지 않았다. 해당 대상의 기존 Finding 수 가정(`finding_count == 2`)이 새 규칙에서 유지되는지는 확인하지 않았다.
