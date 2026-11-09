# P6-A — JavaScript Dynamic Eval 미탐(A8) 원인 연구

> **개정 이력.** P6-A(`d90a43d`)를 P6-A-R 증거 정합성 감사로 개정했다. 감사에서 확인·수정한 내용은 아래와 같다.
>
> - 평가 분모를 명시했다.
> - 모든 사례를 직접 실행해 라벨을 검증했다.
> - 반례 3개를 추가했다.
> - Semgrep 매칭 증거를 직접 수집했다.
> - 확정 사실과 가설을 분리했다.
>
> 기존 라벨은 하나도 바꾸지 않았다. 원래 26개 사례의 수치는 6.1절에 그대로 보존했다.

## 요약과 판정

**판정: `P6_A_RESEARCH_GO`(연구 완료), A8 규칙 수정은 보류.** 제품 규칙(`rules/security-baseline.yml`, SHA-256 `77d085dd…`)은 바꾸지 않았다.

| 구분 | 내용 |
| --- | --- |
| 확정 관찰 | A8(`const eval = globalThis.eval; eval(code)`)과 `let` 변형은 Semgrep 1.182.1 + 운영 규칙에서 미탐이다. 원시 Semgrep과 제품 CLI 모두 0건이다. |
| 확정 관찰 | A8 형태는 실제로 direct eval로 실행된다. Node 24.22.2 `vm`, Chromium 156 classic script에서 확인했다. strict 코드에서는 모든 `eval` 바인딩이 문법 오류다. |
| 직접 증거 | A8 호출은 운영 규칙의 양성 패턴과 일치하고(E2), 동시에 `const eval = $V; ...` 제외 영역 안에 있으며 `$V = globalThis.eval`로 묶인다(E1). |
| 직접 증거 | Semgrep AST에서 이름이 `eval`인 호출은 `Call(Special(Eval))`이고, 다른 이름의 호출은 `Call(Id(...))`이다. |
| 가설 | 후보 B가 A8을 잡지 못하는 이유는, 별칭 추적이 `Special(Eval)` 호출 대상에는 적용되지 않기 때문으로 보인다. 관찰과 일치하지만 Semgrep 내부 구현으로 확인하지는 않았다. |
| 평가 결론 | 세 후보 모두 새 오탐을 만든다. 가장 좁은 후보 A도 29개 사례에서 오탐 3건, strict 문법 오류 파일 보고 1건이 있었다. |

## 1. 시작 Gate와 환경

| 항목 | 값 |
| --- | --- |
| 원격 `main` | `41222b0389fca0ea2e8f37372af3dfcf2008537a`, push CI Run `42651113272` success(필수 3개 Job 성공) |
| 연구 기준 | `dab296e`(원격 `main`과 tree `c2b80ce` 동일). P6-A 커밋 `d90a43d` 위에 P6-A-R 커밋을 새로 추가했다. |
| 브랜치 / Worktree | `research/p6a-dynamic-eval-fn` / P6-A와 같은 연구 전용 worktree |
| 도구 | Semgrep OSS 1.182.1, Node.js 24.22.2, Chromium 156(frontend의 잠금된 `@playwright/test`), Python 3.12(uv) |

연구 자료는 `experiments/p6a-dynamic-eval/`에 있다. `tests/` 밖이므로 CI와 제품에 영향을 주지 않는다. pytest 수집 수는 709개로 변하지 않았다.

## 2. 꼭 알아야 할 JavaScript 기초

### eval, direct eval, indirect eval

`eval(문자열)`은 문자열을 JavaScript 코드로 실행한다. 입력을 공격자가 조종할 수 있으면 임의 코드 실행(CWE-95)이 된다. ECMAScript는 eval 호출을 두 종류로 나눈다.

- **direct eval**: 호출식이 **이름이 `eval`인 식별자**로 시작하고, 그 값이 내장 eval(`%eval%`)일 때다. 호출한 함수의 **지역 변수**를 읽고 쓸 수 있다.
- **indirect eval**: `(0, eval)(x)`, `const run = eval; run(x)`, `globalThis.eval(x)`처럼 다른 형태로 `%eval%`를 부를 때다. **전역 범위**에서만 실행된다.

둘 다 문자열을 코드로 실행하므로 검토 대상이다. direct eval은 지역 변수까지 노출되므로 더 위험하다.

### shadowing, const/let, TDZ, strict 모드

- 함수 안에서 `const eval = ...`을 선언하면, 그 범위에서 `eval`은 전역 eval이 아니라 지역 변수를 가리킨다(shadowing).
- `const`·`let`은 블록 `{ }` 단위로 범위가 생긴다.
- 선언 전에 읽으면 오류가 나는 구간을 TDZ라고 한다.
- `eval`을 변수 이름으로 쓰는 것은 **sloppy script**에서만 허용된다. strict 코드와 ES module에서는 문법 오류다.

### 실험 1: 개념 probe (`semantics/probe.cjs`)

함수 안에 `var secret = 'local'`을 두고, 고정 문자열 `"secret"`만 실행했다.

| 번호 | 코드 | 결과 | 해석 |
| --- | --- | --- | --- |
| S1 | `eval(x)` | `local` | direct eval |
| S2~S4 | `(0, eval)(x)`, `const run = eval; run(x)`, `globalThis.eval(x)` | `ReferenceError: secret is not defined` | indirect eval(전역만 봄) |
| **S5** | **`const eval = globalThis.eval; eval(x)`** | **`local`** | **A8은 direct eval** |
| S6 | `let eval = globalThis.eval` | `local` | direct eval |
| S7 | `const eval = JSON.parse` | `parsed` | 코드 실행 없음 |
| S8 | `eval` 매개변수에 `%eval%` 전달 | `local` | 호출자에 따라 direct eval |
| S9 | `const eval = eval` | `Cannot access 'eval' before initialization` | TDZ 오류로 호출 전 실패 |
| S10 | `const { eval } = globalThis` | `local` | direct eval |
| S11 | 사전에 `globalThis.eval` 교체 | `replaced` | 가정 밖(전역 교체) |

### 실험 2: 사례 파일 직접 실행 (P6-A-R, `semantics/execute_cases.cjs`)

P6-A의 라벨 일부는 위 probe와 **비슷한 형태**를 근거로 붙였다. 예를 들어 N08 `let` 재할당은 S7을 근거로 들었다. 감사에서는 **사례 파일 29개 자체**를 Node `vm`의 새 sloppy 컨텍스트에서 실행했다. 실행한 코드는 고정 문자열 `"typeof arguments"` 하나뿐이다. 결과는 이렇게 읽는다.

- `"object"`: direct eval. 함수의 `arguments`를 본다.
- `"undefined"`: indirect eval. 전역에는 `arguments`가 없다.
- 그 밖의 값이나 JSON 오류: 코드가 실행되지 않았다.

판단 불가 사례(U01~U04)는 서로 다른 호출 상황 두 가지로 실행했다.

결과(`semantics/case-execution.txt`): **29개 모두 라벨과 실행 결과가 일치했다(불일치 0).**

- U01~U04는 상황에 따라 direct eval과 실행 없음이 실제로 갈렸다.
- strict 코드에서는 `const`·`let`·`var`·구조 분해·함수 매개변수·화살표 매개변수 형태의 `eval` 바인딩이 모두 `SyntaxError`였다.

`window` 사례 3개(P07, P11, N07)는 Node에 `window`가 없어서 `window = globalThis`로 흉내 냈다. 그래서 실제 Chromium에서도 classic script로 다시 실행했다(`semantics/browser-window-output.txt`). 결과는 P07 direct eval, P11 indirect eval, N07 실행 없음으로, 라벨과 같았다.

## 3. 기존 규칙 한 줄씩 읽기

```yaml
  - id: baseline.javascript-dynamic-eval
    languages: [javascript, typescript]   # JS·TS 파일 대상
    severity: ERROR                        # 제품에서 high로 표시
    options:
      symbolic_propagation: true           # `const run = eval; run(x)`처럼 한 번 할당된 별칭의 값을 따라감
    patterns:                              # 아래 조건을 모두 만족해야 Finding
      - pattern-either:                    # 다음 중 하나와 모양이 일치하면 후보
          - pattern: eval(...)             # 직접 호출
          - pattern: ($X, eval)(...)       # comma 간접 호출 (0, eval)(x)
          - pattern: new Function(...)     # Function 생성자
          - pattern: Function(...)         # new 없는 Function 호출
      - pattern-not-inside: |              # 제외 1: 매개변수 이름이 eval인 함수 안
          function $F(..., eval, ...) { ... }
      - pattern-not-inside: |              # 제외 2: 매개변수 이름이 Function인 함수 안
          function $F(..., Function, ...) { ... }
      - pattern-not-inside: |              # 제외 3: `const eval = 무엇이든;` 뒤에 오는 모든 문장
          const eval = $V;
          ...
      - pattern-not-inside: |              # 제외 4: `let eval = 무엇이든;` 뒤에 오는 모든 문장
          let eval = $V;
          ...
```

- `$V`, `$F`, `$X`는 메타변수로, "아무 식이나"를 뜻한다.
- `...`는 임의의 문장들로, 중첩 함수 안까지 포함한다.
- `pattern-not-inside`는 "이 모양 안에 있으면 버린다"는 뜻이다.

## 4. 탐지 실패 원인: 증거별 구분

### 4.1 Semgrep 패턴 매칭 증거 (직접 관찰)

- **R0**(운영 규칙): A8 위치에서 결과 0건, 오류 0건, 파일 scanned 1개. 원시 Semgrep과 제품 CLI(`Status: completed`, 같은 폴더의 P01만 보고) 모두 같다.
- **E2**(운영 규칙의 양성 패턴 4개만, 제외 4개 삭제): A8 호출(P05 4행 10열)과 **일치한다**. 미탐은 양성 패턴이 호출을 못 알아봐서가 아니다.
- **E2**는 멤버 호출 `globalThis.eval(...)`(P04), `window.eval(...)`(P11), 멤버 별칭(P13)과는 **일치하지 않는다**. 이 세 미탐은 양성 패턴이 다루지 않는 모양 때문이다.

### 4.2 `pattern-not-inside` 제외 증거

- **직접 증거(E1)**: `pattern: eval(...)` + `pattern-inside: const eval = $V; ...` 탐침은 A8 호출을 보고하고 `$V = globalThis.eval`을 묶는다. A8 호출은 제외 3이 버리는 영역 **안**에 있다. 이 영역 안의 결과를 버리는 것은 `pattern-not-inside`의 정의된 동작이다.
- **반사실 증거(ablation)**: 제외 3만 지운 X3에서 A8이 보고된다. 다른 제외(X1, X2, X4)나 별칭 추적(X5)만 지운 변형에서는 보고되지 않는다.
- **E1이 추가로 보여준 것**: 제외 영역 판정은 범위를 고려하지 않는다.
  - N06은 바로 위 바인딩이 `JSON.parse`인 안쪽 호출인데 `$V = globalThis.eval`로 묶였다(바깥 선언).
  - N09는 지역 객체의 `globalThis.eval`을 그대로 `$V`로 묶었다.
  - P10은 소스가 `const eval = builtin`인데 `$V = globalThis.eval`로 묶였다. 별칭 추적이 `pattern-inside`의 메타변수에도 값을 채운다.

### 4.3 AST 해석 증거 (직접 관찰)

`semgrep --dump-ast -l js`의 호출 노드를 하네스가 추출했다(`results.json`의 `evidence.ast_callees`).

| 사례 | 호출 | Semgrep AST 호출 대상 |
| --- | --- | --- |
| P01 | `eval(code)` | `Call(Special(Eval))` |
| P05(A8) | `eval(code)`, 단 `eval`은 지역 `const` | `Call(Special(Eval))` |
| P03 | `run(code)` (`run = eval`) | `Call(Id(run))` |
| P13 | `evaluate(code)` (`evaluate = globalThis.eval`) | `Call(Id(evaluate))` |

A8의 선언 쪽 `eval`은 dump에서 지역 변수(`LocalVar`)로 해석된다. 그러나 호출 쪽은 이름이 `eval`이라는 이유만으로 내장 형태 `Special(Eval)`이 된다.

### 4.4 아직 추정인 설명

- **가설 H1**: 별칭 추적은 `Id` 호출 대상에만 값을 대입하고 `Special(Eval)`에는 대입하지 않는다.
  - 근거: 후보 B(`globalThis.eval(...)` 패턴 + 별칭 추적)는 P13(`Call(Id(evaluate))`)을 잡지만, 구조가 같고 이름만 `eval`인 P05(`Call(Special(Eval))`)는 잡지 못한다.
  - 관찰과 일치하지만, Semgrep 소스 코드로 확인하지 않았다. 다른 원인(예: 패턴 정규화)도 배제하지 못했다.
- **가설 H2**: 규칙 작성 당시 제외 3·4는 지역 함수 shadowing 오탐만을 의도했고, 내장 eval을 담는 바인딩은 고려하지 않았다. R1-P 기록의 설명과 일치하지만 작성 의도는 직접 확인할 수 없다.

## 5. 반례 검토 (실행 결과 기준)

| 요청 항목 | 사례 | 라벨 | 실행 결과 | 운영 규칙 R0 |
| --- | --- | --- | --- | --- |
| 지역 eval이 JSON.parse 참조 | N01(`const`), N02(`let`) | 음성 | JSON 오류, 코드 실행 없음 | 무시(TN) |
| eval이 전역 내장 함수 참조 | P05 `const`, P06 `let`, P14 `var`, P07 `window.eval`, P08 `globalThis["eval"]`, P10 두 단계, P12 중첩 사용 | 양성 | 모두 direct eval(P07은 Chromium에서도 확인) | `var`(P14)만 탐지, 나머지 6개 미탐 |
| let eval이 호출 전에 재할당 | N08 | 음성 | JSON 오류, 코드 실행 없음 | 무시(TN) |
| 지역 window 객체 | N07 | 음성 | 실행 없음(Node·Chromium) | 무시(TN) |
| 지역 globalThis 바인딩(P6-A-R 추가) | N09 `const eval = globalThis.eval`(지역 객체), N10 `globalThis.eval(x)`(지역 객체) | 음성 | 실행 없음 | 무시(TN) |
| strict / ES module 문법 오류 | I01(strict A8, P6-A-R 추가), `semantics/strict.cjs`, `module.mjs` | `invalid_program` | 로드 시 `SyntaxError` | 보고 안 함 |

**I01은 평가 집계(TP/FP/FN/TN)에서 제외하고 따로 보고한다.** 실행될 수 없는 코드이므로 맞고 틀림을 정할 수 없다. 그러나 X3, 후보 A, 후보 C는 이 파일에도 Finding을 낸다. Semgrep이 실행 모드를 판단하지 않는다는 뜻이다.

## 6. 평가표

### 6.1 26개와 22개 차이의 원인 (P6-A 원래 평가)

P6-A의 26개 사례는 **양성 14 + 음성 8 + 판단 불가 4**였다.

- TP/FP/FN/TN은 정답이 있는 양성·음성 **22개**에만 정의된다.
- 판단 불가 4개(U01~U04)는 "보고함/보고 안 함"으로만 따로 셌다.

원래 보고서의 표는 이 분모와 판단 불가 열을 적지 않아, 22개만 평가한 것처럼 보였다. **집계 자체는 맞았다.** 하네스와 별도로 작성한 재계산 스크립트로 Semgrep을 다시 실행해 9개 변형 모두 같은 값을 얻었고, 라벨 위치 밖의 결과는 0건이었다.

| 변형(P6-A 26개) | TP / FN (양성 14) | FP / TN (음성 8) | 판단 불가 4 중 보고 |
| --- | --- | --- | --- |
| R0 운영 규칙 | 5 / 9 | 0 / 8 | 0 |
| 후보 A | 10 / 4 | 2 / 6 | 0 |
| 후보 B | 8 / 6 | 1 / 7 | 0 |
| 후보 C | 11 / 3 | 6 / 2 | 3 |

### 6.2 검증된 평가표 (P6-A-R 29개)

29개 = 양성 14 + 음성 10 + 판단 불가 4 + 문법 오류 1. TP/FP/FN/TN 분모는 24개다.

| 변형 | TP / FN (양성 14) | FP / TN (음성 10) | 판단 불가 4 중 보고 | 문법 오류 1 보고 | native rule test |
| --- | --- | --- | --- | --- | --- |
| R0 운영 규칙 | 5 / 9 | 0 / 10 | 0 | 0 | 통과 |
| X1 제외 1 삭제 | 5 / 9 | 0 / 10 | 1 | 0 | 실패(`ok` 56, 124) |
| X2 제외 2 삭제 | 5 / 9 | 0 / 10 | 0 | 0 | 실패(`ok` 71, 141) |
| X3 제외 3 삭제 | 10 / 4 | 5 / 5 | 3 | 1 | 실패(`ok` 63, 133) |
| X4 제외 4 삭제 | 6 / 8 | 2 / 8 | 0 | 0 | **통과**(테스트 공백) |
| X5 별칭 추적 끄기 | 4 / 10 | 0 / 10 | 0 | 0 | 실패(`ruleid` 28, 34, 116) |
| **후보 A** | 10 / 4 | **3** / 7 (N06, N08, N09) | 0 | **1** | 통과 |
| **후보 B** | 8 / 6 | **2** / 8 (N07, N10) | 0 | 0 | 통과 |
| **후보 C** | 11 / 3 | **7** / 3 | 3 | 1 | 실패(`ok` 63, 133) |

다른 코퍼스에서 R0 대비 달라진 점은 다음과 같다.

- **R1 dev 41 / held-out 18**: R0는 R1-P 기록과 정확히 같다(dev TP 22/FP 2/FN 1/TN 16, held-out TP 7/FP 1/FN 5/TN 5). 후보 A는 변화 없음, 후보 B는 held-out H01·H02 FN→TP, 후보 C·X3는 dev `block_shadow` TN→FP, X1은 dev `parameter_shadow` TN→FP, X2는 held-out H13 TN→FP, X5는 별칭 TP 6건 손실.
- **6A / 6D / 6E 코퍼스**: 후보 A·B·C 모두 매치 변화가 없다. X5만 6D `EJ08`, 6E `EJX11`을 잃는다.
- **Semgrep 오류**: 모든 변형에서 R1 `ind1/syntax_error.js`(의도적 문법 오류, R1 라벨 `invalid_program`) 1건으로 같다.

### 6.3 후보 평가

| 후보 | 해결한 미탐 | 새 오탐과 원인 |
| --- | --- | --- |
| A: `const`/`let eval = globalThis.eval or window.eval` 뒤의 `eval(...)` 재포함 | A8 계열 5개(P05, P06, P07, P10, P12) | 범위를 모르는 영역 판정(N06 안쪽 재선언, N08 재할당), 지역 `globalThis` 객체(N09), strict 문법 오류 파일(I01) |
| B: `globalThis.eval(...)`/`window.eval(...)` 가지 추가 | 멤버 호출 3개(P04, P11, P13), R1 held-out 2개. **A8은 해결 못 함** | 지역 `window`(N07), 지역 `globalThis`(N10) 객체 |
| C: `const`/`let` 제외 삭제 | A8 계열 6개 | 7건. R1-P 이전의 shadowing 오탐이 되살아나고 기존 테스트가 실패 |

- **성능**: 211개 파일에서 변형별 5회 측정한 마지막 실행의 중앙값은 1.98~2.05초였다(R0 2.05초, `results/timing.json`). 그러나 P6-A 측정에서는 같은 변형 안에서도 2.8~4.8초로 흔들렸다. 실행 환경의 부하가 규칙 간 차이보다 크므로 성능 차이에 대한 결론은 내리지 않는다.
- **유지보수**: 후보 A는 패턴 모양을 열거하므로 변형마다 패턴을 늘려야 한다. 후보 B는 패턴 2개다. 두 후보 모두 규칙 바이트가 바뀌어 Rule Bytes Identity 비교는 `DIFFERENT_SELECTED_BYTES`가 된다.

### 6.4 권고

A8 수정은 **보류**한다.

- 가장 좁은 후보 A도 오탐 3건과 문법 오류 파일 보고를 만든다.
- A8 수용 기준 중 R1-P-R1 probe, A1 DET, SA-1 재실행과 성능 기준은 확인하지 못했다.
- 실제 코드에서의 빈도는 알 수 없다.

후보 B는 A8과 **다른 미탐 유형**(멤버 호출)을 다룬다. 지역 `window`/`globalThis` 객체 오탐이 있으므로, 후속 단계에서 별도로 검토할 가치가 있다는 정도의 가설로만 남긴다.

**발견한 기존 테스트 공백(수정하지 않음)**: fixture에 같은 함수 안 `let eval = JSON.parse; eval(x)` 형태의 `ok` 사례가 없다. 그래서 제외 4를 지운 X4가 native rule test를 통과한다.

## 7. 재현 명령과 기대 결과

```sh
# 1) A8 단일 재현 (원시 Semgrep)
semgrep scan --metrics=off --disable-version-check --config rules/security-baseline.yml \
  --json experiments/p6a-dynamic-eval/cases/P05_a8_const_global_this.js
# 기대: "results": [], "errors": [], scanned 파일 1개

# 2) 제품 CLI로 재현 (tests/ 밖의 임시 폴더에 복사)
T="$(mktemp -d)"
cp experiments/p6a-dynamic-eval/cases/P0{1_direct_eval,5_a8_const_global_this}.js "$T"/
uv run --locked python -m ai_code_security_analyzer scan --path "$T" --rules rules/security-baseline.yml
# 기대: Status: completed, P01_direct_eval.js:3 한 건만 보고

# 3) 라벨 실행 검증 (Node 24; 고정 문자열만 실행)
node experiments/p6a-dynamic-eval/semantics/execute_cases.cjs
# 기대: "# sites=29 disagreements=0", 종료 코드 0, semantics/case-execution.txt와 같은 출력

# 4) window 사례 실제 브라우저 검증 (frontend에서 npm ci 후)
node experiments/p6a-dynamic-eval/semantics/browser_window_cases.cjs
# 기대: P07 direct-eval, P11 indirect-eval, N07 no-eval

# 5) 개념 probe와 AST
node experiments/p6a-dynamic-eval/semantics/probe.cjs        # semantics/probe-output.txt와 같음
semgrep --dump-ast -l js experiments/p6a-dynamic-eval/cases/P05_a8_const_global_this.js   # Call(Special((Eval, ())), ...)

# 6) 전체 하네스 (R1 자료는 연구 커밋에서 읽기 전용으로 추출)
R1="$(mktemp -d)"
git archive ff88612112a62a524f13464a9a163be5469e0f96 experiments/r1-detection/cases experiments/r1-detection/labels.json | tar -x -C "$R1"
uv run --locked python -I experiments/p6a-dynamic-eval/run_p6a.py \
  --r1-root "$R1/experiments/r1-detection" --timing-runs 5 --check-rules
# 기대: 6.2절 수치, R0의 R1 수치가 R1-P 기록과 같음.
#       results/results.json은 바이트 단위로 같게 재생성됨(시간 값은 results/timing.json에만 기록).
```

## 8. 확정 사실, 가설, 한계

**확정 사실(실행 관찰)**

- 운영 규칙 `77d085dd…` + Semgrep 1.182.1에서 A8과 `let` 변형은 미탐이다(원시 Semgrep, 제품 CLI).
- 29개 사례 모두 실행 결과가 라벨과 일치한다(Node `vm`). `window` 사례 3개는 Chromium에서도 일치한다.
- A8 형태는 sloppy script에서 direct eval이고, strict 코드에서는 모든 `eval` 바인딩 형태가 문법 오류다.
- A8 호출은 양성 패턴과 일치하고(E2) 제외 3의 영역 안에 있다(E1). 제외 3만 지우면 보고된다(X3).
- 이름이 `eval`인 호출은 Semgrep AST에서 `Special(Eval)`이다.
- 제외 영역 판정은 가장 가까운 바인딩을 고려하지 않는다(E1의 N06).
- 하네스는 R1-P 기록의 R1 수치를 재현하고, 별도 재계산과 같은 집계를 낸다. `results.json`은 재실행 시 바이트 단위로 같다.

**가설**

- H1(4.4절): 별칭 추적이 `Special(Eval)` 호출 대상에 적용되지 않는다.
- H2(4.4절): 제외 3·4의 원래 의도.
- 후보 B를 별도 유형으로 검토할 가치가 있다는 권고.

**한계**

- 모든 사례는 작은 합성 집합이고, 같은 사람이 만들고 라벨을 붙였다. 독립 검토는 없었다. P6-A-R의 실행 검증은 라벨이 "실행 의미와 일치함"을 보이지만, 사례 선택의 편향은 해결하지 못한다.
- 실제 저장소에서 A8의 빈도와 보안 영향(입력 출처, 도달성, 악용 가능성)은 측정하지 않았다.
- 실행 검증은 Node 24 `vm`과 Chromium 156 한정이다. 다른 엔진과 사전에 전역 eval을 교체한 환경은 가정 밖이다.
- R1-P-R1 probe, A1 DET, SA-1 사례는 `main`에 없어 재실행하지 않았다. 성능 차이는 측정 잡음보다 작아 판단하지 않았다.

## 9. 연습문제

정답은 하네스나 `execute_cases.cjs`를 직접 실행해 확인할 수 있다.

**문제 1.** 다음 두 함수에서 지역 `secret`을 읽을 수 있는 쪽은 어디인가? 그리고 운영 규칙이 각각을 탐지하는가?

```js
function a(code) { var secret = 1; const e = globalThis.eval; return e(code); }
function b(code) { var secret = 1; const eval = globalThis.eval; return eval(code); }
```

<details><summary>해설</summary>

`b`만 지역 `secret`을 읽는다(direct eval). `a`는 이름이 `eval`이 아니므로 indirect eval이다. 운영 규칙은 둘 다 탐지하지 못한다. `a`는 멤버 별칭 미탐(P13, 양성 패턴이 다루지 않음), `b`는 A8(P05, 제외 3이 버림)이다.
</details>

**문제 2.** 규칙에서 `let eval = $V` 제외를 지워도 기존 `semgrep --test`가 통과한다. 왜 그런가? 그리고 이 공백을 드러내려면 fixture에 어떤 `ok` 사례 한 줄을 추가하면 되는가?

<details><summary>해설</summary>

fixture의 `let eval` 사례(`nestedHelperLet`)는 중첩 helper 안에 있다. 테스트 대상인 바깥 `eval(code)`는 원래 `ruleid`라서, 제외를 지워도 판정이 바뀌지 않는다. 같은 함수 안에서 지역 `let eval = JSON.parse;` 뒤에 `eval(text)`를 부르는 사례에 `// ok:`를 붙이면, 제외 삭제 시 테스트가 실패한다(이 연구의 N02).
</details>

**문제 3.** 후보 A는 아래 코드에서 오탐을 낸다. 언어 의미상 `eval(code)`는 무엇을 호출하는가? 그리고 E1 탐침이 이 사례에서 `$V`를 무엇으로 묶었는지 생각해 보자.

```js
function run(code) {
  const globalThis = { eval: (v) => v };
  const eval = globalThis.eval;
  return eval(code);
}
```

<details><summary>해설</summary>

지역 객체 `globalThis`의 `eval` 속성, 즉 입력을 그대로 돌려주는 함수다. 코드는 실행되지 않는다(N09, 실행 검증: `returned "typeof arguments"`). E1은 `$V = globalThis.eval`로 묶었다. 패턴은 글자 모양만 비교하고, 그 `globalThis`가 진짜 전역인지는 판단하지 않는다.
</details>
