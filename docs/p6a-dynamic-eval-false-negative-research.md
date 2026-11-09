# P6-A — JavaScript Dynamic Eval 미탐(A8) 원인 연구

## 요약과 판정

**판정: `P6_A_RESEARCH_GO`.** 연구는 완료됐다. 제품 규칙은 바꾸지 않으며, 이번 근거만으로는 수정을 권고할 만큼 정확성이 입증되지 않았다.

- A8 미탐을 Semgrep 1.182.1과 변경하지 않은 `rules/security-baseline.yml`(SHA-256 `77d085dd…`)로 재현했다. 원시 Semgrep 실행과 제품 CLI 모두에서 Finding 0건이다.
- Node 24.22.2 실험으로 A8의 `eval(code)`가 **direct eval**(지역 변수를 읽을 수 있는 eval)임을 확인했다. 따라서 이 미탐은 실제 동적 코드 실행 신호의 누락이다.
- 원인은 두 가지가 겹친 것이다.
  1. 규칙의 `const eval = $V; ...` 제외가 `$V`의 값을 보지 않는다.
  2. Semgrep은 `eval(...)` 호출을 지역 변수 참조가 아닌 **특수 내장 형태**(`Special(Eval)`)로 해석한다. 그래서 지역 바인딩의 값을 호출에 연결하지 않는다.
- 개선 후보 3개를 측정했다. 어느 후보도 새 오탐 없이 A8 계열 전체를 해결하지 못했다. 가장 범위가 좁은 후보 A는 기존 테스트·R1·6A/6D/6E 결과를 바꾸지 않았지만, 새 합성 사례에서 오탐 2건을 만들었다.
- 기존 테스트의 공백도 발견했다. 지역 `let eval = JSON.parse` 같은 `ok` 사례가 없어서, `let` 제외를 지워도 현재 native rule test가 통과한다.

## 1. 시작 Gate와 환경

| 항목 | 값 |
| --- | --- |
| 원격 `main` | `41222b0389fca0ea2e8f37372af3dfcf2008537a` (P5 병합, PR #8) |
| Push CI | Run `42651113272` completed/success; Python, Semgrep 1.182.1, React 3개 Job 성공 |
| 연구 기준 커밋 | `dab296e`. `41222b0`과 tree(`c2b80ce`)가 같아 fetch 없이 분기했다. |
| 브랜치 / Worktree | `research/p6a-dynamic-eval-fn` / 별도 연구 전용 worktree |
| 도구 | Semgrep OSS 1.182.1, Node.js 24.22.2, Python 3.12(uv 잠금 환경) |
| 제품 규칙 | 읽기만 했다. 하네스가 실행 전에 SHA-256 `77d085dd4901863f8873c987f70d6ccd376ab33590724a1389885df09d5ff9df`를 확인한다. |

연구 자료는 모두 `experiments/p6a-dynamic-eval/`에 있다. `tests/` 밖이므로 CI와 제품 실행에 영향을 주지 않는다.

## 2. 꼭 알아야 할 JavaScript 기초

### eval, direct eval, indirect eval

`eval(문자열)`은 문자열을 JavaScript 코드로 실행한다. 입력을 공격자가 조종할 수 있으면 임의 코드 실행(CWE-95)이 된다.

ECMAScript는 eval 호출을 두 종류로 나눈다.

- **direct eval**: 호출식이 `eval(...)`처럼 **이름이 `eval`인 식별자**로 시작하고, 그 값이 내장 eval(명세 표기 `%eval%`)일 때다. 호출한 함수의 **지역 변수**를 읽고 쓸 수 있다.
- **indirect eval**: `(0, eval)(x)`, `const run = eval; run(x)`, `globalThis.eval(x)`처럼 다른 형태로 `%eval%`를 부를 때다. **전역 범위**에서만 실행된다.

어느 쪽이든 문자열을 코드로 실행하므로 보안 검토 대상이다. direct eval은 지역 변수까지 노출되므로 더 위험하다.

### shadowing과 const/let/TDZ

함수 안에서 `const eval = ...`을 선언하면 그 범위에서 `eval`이라는 이름은 전역 eval이 아니라 **지역 변수**를 가리킨다. 이것을 shadowing(가림)이라고 한다. `const`·`let`은 블록 `{ }` 단위로 범위가 생긴다. 선언 전에 읽으면 오류가 나는 구간을 TDZ(Temporal Dead Zone)라고 한다.

`eval`을 변수 이름으로 쓰는 것은 **sloppy script**(엄격 모드가 아닌 일반 스크립트)에서만 허용된다. `'use strict'` 코드와 ES module에서는 문법 오류다.

### 실험으로 확인한 의미 (`semantics/probe.cjs`, Node 24.22.2)

고정 문자열 `"secret"`만 실행해서, 지역 변수 `secret = 'local'`이 보이는지 확인했다.

| 번호 | 코드 | 결과 | 해석 |
| --- | --- | --- | --- |
| S1 | `eval(x)` | `local` | direct eval |
| S2 | `(0, eval)(x)` | `ReferenceError: secret is not defined` | indirect eval(지역 변수를 못 봄) |
| S3 | `const run = eval; run(x)` | 같음 | indirect eval |
| S4 | `globalThis.eval(x)` | 같음 | indirect eval |
| **S5** | **`const eval = globalThis.eval; eval(x)`** | **`local`** | **A8: direct eval** |
| S6 | `let eval = globalThis.eval; eval(x)` | `local` | A8의 `let` 변형도 direct eval |
| S7 | `const eval = JSON.parse; eval(...)` | `parsed` | 코드 실행 아님 |
| S8 | `eval` 매개변수에 `%eval%` 전달 | `local` | 호출자에 따라 direct eval이 될 수 있음 |
| S9 | `const eval = eval` | `Cannot access 'eval' before initialization` | TDZ 오류로 호출 전에 실패 |
| S10 | `const { eval } = globalThis` | `local` | 구조 분해도 direct eval |
| S11 | 사전에 `globalThis.eval` 교체 | `replaced` | 전역을 바꾸면 의미가 달라짐(가정 밖) |

엄격 모드 스크립트와 ES module에서는 A8 코드가 `SyntaxError: Unexpected eval or arguments in strict mode`였다. **A8은 sloppy script에서만 존재한다.**

S2~S4가 `global-only`가 아니라 `ReferenceError`인 이유는 CommonJS가 최상위 `var secret`을 전역이 아닌 모듈 범위에 두기 때문이다. 핵심은 지역 값 `local`을 보지 못했다는 점이다.

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

- `$V`, `$F`, `$X`는 **메타변수**로, "아무 식이나"를 뜻한다.
- `...`는 "임의의 문장들"로, 중첩된 함수 안까지 포함한다.
- `pattern-not-inside`는 "이 모양 안에 있으면 버린다"는 뜻이다.

제외 3과 4는 `const eval = JSON.parse; eval(text)`처럼 지역 함수를 부르는 오탐을 막으려고 R1-P에서 추가됐다.

## 4. 탐지 실패의 실제 원인

### 원인 1: 제외가 값을 보지 않는다

제외 3의 `$V`는 어떤 값과도 일치한다. 그래서 `const eval = globalThis.eval;`도 지역 함수 선언과 똑같이 취급되고, 뒤따르는 `eval(code)`가 버려진다. 하나씩 빼 보는 실험(ablation)이 이를 직접 보여준다.

| 변형 | 바뀐 점 | A8(P05) | 함께 생긴 변화 |
| --- | --- | --- | --- |
| R0 | 제품 규칙 그대로 | 미탐 | — |
| X3 | 제외 3(`const`)만 삭제 | **탐지** | 오탐 4건(N01, N03, N04, N06), fixture `ok` 63·133행 실패, R1 `block_shadow` 오탐 |
| X4 | 제외 4(`let`)만 삭제 | 미탐(P06 `let` 변형은 탐지) | 오탐 2건(N02, N08). **기존 fixture 테스트는 통과** |
| X1 | 제외 1 삭제 | 미탐 | fixture `ok` 56·124행 실패, R1 `parameter_shadow` 오탐 |
| X2 | 제외 2 삭제 | 미탐 | fixture `ok` 71·141행 실패, R1 H13 오탐 |
| X5 | 별칭 추적 끄기 | 미탐 | 별칭 TP 손실: P03, R1 dev 5건·held-out 1건, 6D `EJ08`, 6E `EJX11` |

**A8을 숨기는 것은 제외 3 하나뿐**이다. 나머지 제외도 각각 기존 `ok` 테스트나 R1 음성 사례를 지키는 역할이 있다.

### 원인 2: Semgrep은 `eval(...)`을 특수 형태로 본다

`semgrep --dump-ast -l js cases/P05_a8_const_global_this.js` 출력을 요약하면 다음과 같다(원문은 직접 실행해 확인할 수 있다).

```text
DefStmt( name = Id("eval", { id_resolved = LocalVar }), VarDef(vinit = DotAccess(Id "globalThis", "eval")) )
Return( Call( Special((Eval, ())), [Arg(Id "code")] ) )
```

선언 쪽 `eval`은 지역 변수(`LocalVar`)로 해석된다. 그러나 호출 쪽은 **변수 참조가 아니라 `Special(Eval)`이라는 내장 형태**다. 그래서 다음 두 가지가 성립한다.

- `pattern: eval(...)`은 지역 바인딩과 무관하게 항상 일치한다. 그래서 지역 함수를 가리기 위한 제외 3이 필요했다.
- 별칭 추적(symbolic propagation)은 식별자에 적용되므로, 지역 변수의 값(`globalThis.eval`)이 이 호출에 연결되지 않는다. 후보 B 실험이 이 예측을 확인했다(아래).

즉 **"언어 의미상 direct eval"**과 **"Semgrep이 보는 구문 모양"**이 어긋난다. 규칙은 이 차이를 구문 제외로 메우는데, 그 제외가 너무 넓다.

## 5. 반례 조사 (제품 규칙 R0 기준)

`experiments/p6a-dynamic-eval/cases/`의 합성 사례 26개다. 라벨은 위 Node 실험(`labels.json`의 `probe`)으로 근거를 붙였다.

| 분류 | 사례 |
| --- | --- |
| **TP(맞게 탐지) 5** | P01 `eval(x)`, P02 comma, P03 별칭, P09 구조 분해 `const { eval } = globalThis`(제외 3과 모양이 달라 탐지), P14 `var eval = globalThis.eval`(var 제외 없음) |
| **FN(미탐) 9** | **A8 계열 6**: P05 `const`(A8), P06 `let`, P07 `window.eval`, P08 `globalThis["eval"]`, P10 두 단계 별칭, P12 중첩 함수에서 사용. **멤버 호출 3**: P04 `globalThis.eval(x)`, P11 `window.eval(x)`, P13 `const e = globalThis.eval; e(x)` |
| **TN(맞게 무시) 8** | N01 `const eval = JSON.parse`, N02 `let` 동일, N03 지역 함수, N04 TDZ 자기참조, N05 `policy.eval`, N06 A8 안쪽 블록 shadowing, N07 지역 `window` 객체, N08 `let` 재할당 |
| **FP(오탐) 0** | 이 합성 집합에서는 없음. 기존 기록의 sloppy-only 오탐(`var eval`, `function eval`, 화살표 매개변수)은 fixture `todook`으로 계속 남아 있다. |
| **판단 불가 4** | U01 `eval` 매개변수(호출자에 따라 다름, S8), U02 알 수 없는 함수의 반환값, U03 조건식 `useNative ? globalThis.eval : JSON.parse`, U04 설정값. R0는 모두 보고하지 않는다. |

## 6. 개선 후보 평가

세 후보 모두 하네스가 제품 규칙 텍스트에서 자동으로 만든다(`rules/CA.yml`, `CB.yml`, `CC.yml`). **제품 규칙 파일은 바꾸지 않았다.**

- **후보 A(CA)**: 기존 규칙을 그대로 두고, `const|let eval = globalThis.eval | window.eval` 뒤의 `eval(...)`만 다시 포함하는 가지를 추가한다.
- **후보 B(CB)**: `globalThis.eval(...)`, `window.eval(...)` 호출 가지를 추가하고, 별칭 추적이 A8까지 이어지는지 본다.
- **후보 C(CC)**: `const`·`let` 제외 두 개를 삭제한다.

| 항목 | R0 | 후보 A | 후보 B | 후보 C |
| --- | --- | --- | --- | --- |
| P6-A 합성 TP / FP / FN / TN | 5 / 0 / 9 / 8 | 10 / **2** / 4 / 6 | 8 / **1** / 6 / 7 | 11 / **6** / 3 / 2 |
| 해결한 미탐 | — | A8 계열 5(P05, P06, P07, P10, P12) | 멤버 호출 3(P04, P11, P13). **A8은 해결 못 함** | A8 계열 6 |
| 새 오탐 | — | N06 안쪽 블록 shadowing, N08 `let` 재할당 | N07 지역 `window` 객체 | N01, N02, N03, N04, N06, N08 |
| 판단 불가 사례 보고 | 0 | 0 | 0 | 3 |
| 기존 native rule test | 통과 | 통과 | 통과 | **실패**(`ok` 63·133행) |
| fixture A8 `todoruleid`(212행) | 미보고 | 보고 | 미보고 | 보고 |
| R1 dev / held-out 변화 | 기준 | 없음 | held-out H01·H02 FN→TP | dev `block_shadow` TN→FP |
| 6A / 6D / 6E 매치 변화 | 기준 | 없음 | 없음 | 없음 |
| Semgrep 오류 | 1(R1 의도적 문법 오류 파일) | 동일 | 동일 | 동일 |

### 새 오탐 가능성 분석

- **후보 A**는 "그 지점에서 `eval`이 무엇을 가리키는가"를 직접 알지 못한다. 그래서 안쪽 블록의 재선언(N06)이나 재할당(N08)을 놓친다. 이를 막으려면 범위 분석을 패턴으로 흉내 내야 하는데, R1-P-R1에서 같은 방식(`...`의 중첩 범위 매치)이 실제 탐지 손실을 만든 전례가 있다.
- **후보 A**는 허용 목록 방식이라 `globalThis["eval"]`(P08)이나 두 단계 이상 변형을 놓칠 수 있다. P10은 별칭 추적 덕분에 잡혔다.
- **후보 B**는 A8 해결책이 아니다. 대신 다른 미탐 유형(멤버 호출)을 줄인다. `window`라는 이름의 지역 객체(N07)에서 오탐이 난다.
- **후보 C**는 R1-P 이전의 shadowing 오탐을 되살리고 기존 테스트를 깨뜨린다. 채택할 수 없다.

### 성능과 유지보수 비용

- **성능**: 211개 파일 작업 공간에서 변형별 5회 측정한 중앙값은 2.8~3.8초였다. 같은 변형 안에서도 2.8~4.8초로 흔들렸다. 패턴을 **빼기만 한** X3(3.80초)가 R0(2.94초)보다 느렸으므로, 차이는 규칙 비용이 아니라 측정 잡음으로 본다. A8 수용 기준의 "±20% 이내"는 **검증하지 못했다**. 조용한 환경에서 반복 측정이 필요하다.
- **유지보수**: 후보 A는 가지 1개, `pattern-inside` 4개를 더한다. 모양을 열거하므로 새 변형마다 패턴을 늘려야 한다. 후보 B는 패턴 2개를 더하고, 의미가 단순해서 이해하기 쉽다. 두 후보 모두 Finding ID 계산 방식은 바뀌지 않는다. 다만 규칙 바이트가 바뀌므로 Rule Bytes Identity 비교는 `DIFFERENT_SELECTED_BYTES`가 된다(기존 R1-P와 같은 기대 동작).

### 권고

A8 수정은 **보류**한다. 근거는 다음과 같다.

- A8 문서의 수용 기준 중 일부만 확인됐다. `ok` 유지, R1 dev/held-out에서 사라진 TP 0건, 6A/6D/6E 불변은 충족했다. R1-P-R1 probe, A1 DET, SA-1 사례 재실행과 성능 기준은 확인하지 못했다.
- 가장 나은 후보 A도 합성 오탐 2건을 만들었다.
- A8은 sloppy script 한정의 부자연스러운 형태다. 실제 코드에서의 빈도는 측정되지 않았다.

후속 단계가 생긴다면, 후보 B(멤버 호출)를 A8과 **별개의 미탐 유형**으로 먼저 검토하는 편이 위험이 낮아 보인다. 이것도 가설이며 이번 연구로 입증하지 않았다.

### 발견한 기존 테스트 공백(수정하지 않음)

현재 fixture에는 함수 안 `let eval = JSON.parse; eval(x)` 같은 `ok` 사례가 없다. X4(제외 4 삭제)가 native rule test를 통과하면서 합성 오탐 2건을 만든 것이 그 증거다. 기존 테스트는 이번 범위에서 수정하지 않았다. 후속 단계에서 `ok` 사례를 추가할 것을 제안한다.

## 7. 재현 명령과 기대 결과

```sh
# 1) A8 단일 재현 (원시 Semgrep)
semgrep scan --metrics=off --disable-version-check --config rules/security-baseline.yml \
  --json experiments/p6a-dynamic-eval/cases/P05_a8_const_global_this.js
# 기대: "results": [], "errors": [], 파일 1개 scanned

# 2) 제품 CLI로 재현 (tests/ 밖의 임시 폴더에 복사)
T="$(mktemp -d)"
cp experiments/p6a-dynamic-eval/cases/P0{1_direct_eval,5_a8_const_global_this}.js "$T"/
uv run --locked python -m ai_code_security_analyzer scan --path "$T" --rules rules/security-baseline.yml
# 기대: Status: completed, P01_direct_eval.js:3 한 건만 보고, P05는 보고되지 않음

# 3) JavaScript 의미 확인 (고정 문자열만 실행하는 합성 probe)
node experiments/p6a-dynamic-eval/semantics/probe.cjs
# 기대: experiments/p6a-dynamic-eval/semantics/probe-output.txt와 같은 출력

# 4) Semgrep AST 확인
semgrep --dump-ast -l js experiments/p6a-dynamic-eval/cases/P05_a8_const_global_this.js
# 기대: 호출이 Call(Special((Eval, ())), ...)로 표시됨

# 5) 전체 하네스 (R1 자료는 연구 커밋에서 읽기 전용으로 추출)
R1="$(mktemp -d)"
git archive ff88612112a62a524f13464a9a163be5469e0f96 experiments/r1-detection/cases experiments/r1-detection/labels.json | tar -x -C "$R1"
uv run --locked python -I experiments/p6a-dynamic-eval/run_p6a.py \
  --r1-root "$R1/experiments/r1-detection" --timing-runs 5 --check-rules
# 기대: R0 행이 P6A TP=5 FP=0 FN=9 TN=8, R1 dev TP=22/FP=2/FN=1/TN=16, heldout TP=7/FP=1/FN=5/TN=5
#       (R1 수치는 R1-P 기록과 같아야 한다), results/results.json 재생성
```

결과 파일 `experiments/p6a-dynamic-eval/results/results.json`에는 변형별 사례 판정, fixture 주석별 보고 여부, native rule test 요약, R1·벤치마크 차이, 실행 시간이 있다. 임시 경로는 기록하지 않는다. 시간 값은 실행 환경에 따라 달라진다.

## 8. 증명한 것과 증명하지 못한 것

**증명한 것**

- 제품 규칙(`77d085dd…`)과 Semgrep 1.182.1에서 A8(`const`)과 `let` 변형이 미탐이다. 원시 Semgrep과 제품 CLI 모두에서 확인했다.
- Node 24.22.2에서 A8 형태는 direct eval로 동작한다(sloppy CommonJS). strict·module에서는 문법 오류다.
- A8을 숨기는 것은 `const eval = $V` 제외 하나뿐이다(ablation).
- Semgrep은 호출을 `Special(Eval)`로 표현한다. 별칭 추적을 이용하는 후보 B가 A8을 잡지 못한 것은 이 해석과 일치한다.
- 하네스는 R1-P 기록의 R1 수치를 정확히 재현했다. 따라서 후보 비교에 사용한 채점 방식은 기존 연구와 같다.

**증명하지 못한 것**

- 후보 규칙이 실제 코드에서 더 정확하다는 것. 모든 평가는 작은 합성 집합이고, 같은 사람이 사례와 라벨을 만들었다. 독립 검토는 없었다.
- 실제 저장소에서 A8 형태의 빈도와 보안 영향. 입력 출처·도달성·악용 가능성은 판단하지 않았다.
- 브라우저에서의 `window` 사례 동작. Node에는 `window`가 없어 S4·S5와 같은 구조라는 추론에 의존한다.
- 성능 ±20% 기준(측정 잡음이 더 큼). R1-P-R1 probe, A1 DET, SA-1 사례의 재실행.
- Semgrep 내부 구현 자체. AST 출력과 관찰된 동작에서 추론했을 뿐이다.

## 9. 연습문제

정답은 하네스를 직접 실행해 확인할 수 있다. 접힌 해설은 먼저 풀어 본 뒤 열어 보자.

**문제 1.** 다음 두 함수에서 `secret`을 읽을 수 있는 쪽은 어디인가? 그리고 운영 규칙이 각각을 탐지하는가?

```js
function a(code) { var secret = 1; const e = globalThis.eval; return e(code); }
function b(code) { var secret = 1; const eval = globalThis.eval; return eval(code); }
```

<details><summary>해설</summary>

`b`만 지역 `secret`을 읽는다(direct eval, S5). `a`는 이름이 `eval`이 아니므로 indirect eval이다(S3/S4). 운영 규칙은 둘 다 탐지하지 못한다. `a`는 멤버 별칭 미탐(P13), `b`는 A8(P05)이다. 위험도는 지역 변수를 노출하는 `b`가 더 크다.
</details>

**문제 2.** 규칙에서 `let eval = $V` 제외를 지워도 기존 `semgrep --test`가 통과한다. 왜 그런가? 그리고 이 공백을 드러내려면 fixture에 어떤 `ok` 사례 한 줄을 추가하면 되는가?

<details><summary>해설</summary>

fixture의 `let eval` 사례(`nestedHelperLet`)는 중첩 helper 안에 있다. 테스트 대상인 바깥 `eval(code)`는 원래 `ruleid`라서, 제외를 지워도 판정이 바뀌지 않는다. 같은 함수 안에서 지역 `let eval = JSON.parse;` 뒤에 `eval(text)`를 부르는 사례에 `// ok:`를 붙이면, 제외 삭제 시 테스트가 실패한다(이 연구의 N02).
</details>

**문제 3.** 후보 A는 아래 코드에서 오탐을 낸다. 언어 의미상 `eval(text)`는 무엇을 호출하는가? 그리고 Semgrep 패턴만으로 이 오탐을 막기 어려운 이유는 무엇인가?

```js
function run(text) {
  const eval = globalThis.eval;
  { const eval = JSON.parse; return eval(text); }
}
```

<details><summary>해설</summary>

안쪽 블록의 `const eval`이 바깥 바인딩을 가리므로 `JSON.parse`를 호출한다(N06). 막으려면 "가장 가까운 바인딩"을 판단해야 한다. 그런데 `pattern-inside`의 `...`는 중첩 범위까지 넓게 일치한다. 범위를 패턴으로 흉내 내면 R1-P-R1처럼 바깥 범위의 실제 호출까지 숨길 위험이 있다.
</details>
