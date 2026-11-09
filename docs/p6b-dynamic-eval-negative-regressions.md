# P6-B — Dynamic Eval 오탐 회귀 테스트 강화

## 요약

운영 Semgrep 규칙 `baseline.javascript-dynamic-eval`(`rules/security-baseline.yml`, SHA-256 `77d085dd…`)은 **바꾸지 않았다**. 대신 실행으로 음성임을 확인한 사례 8개를 기존 native rule test fixture에 `ok` 주석으로 추가했다.

- **변경 전**: 알려진 위험한 규칙 변형 5개 중 3개가 기존 테스트를 그대로 통과했다. 이 3개는 `let` 제외 삭제(X4), P6-A 후보 A(CA), 후보 B(CB)로, 모두 실제 오탐을 만드는 변형이다.
- **변경 후**: 5개 변형 모두 테스트에서 실패한다. 운영 규칙은 계속 통과한다.
- **이번 변경은 탐지 성능을 높이지 않는다.** 이미 올바르게 무시하던 음성 사례가 앞으로도 무시되도록 고정할 뿐이다. 미탐(A8 등)은 그대로 남는다.

## 1. 시작 Gate

| 항목 | 값 |
| --- | --- |
| 원격 `main` | `41222b0389fca0ea2e8f37372af3dfcf2008537a`, push CI Run `42651113272` success(필수 3개 Job 성공) |
| 시작 커밋 | `dab296e`(원격 `main`과 tree `c2b80ce` 동일). fetch 없이 새 분리 worktree에서 시작했다. |
| 브랜치 | `test/p6b-dynamic-eval-negative-regressions`(연구 브랜치 `research/p6a-dynamic-eval-fn`과 분리) |
| 도구 | Semgrep OSS 1.182.1, Node.js 24.22.2, Python 3.12(uv) |

## 2. 꼭 알아야 할 개념

### Shadowing(가림)

안쪽 범위에서 바깥과 **같은 이름의 변수**를 새로 선언하면, 그 범위 안에서는 그 이름이 새 변수를 가리킨다. 이것을 shadowing이라고 한다.

```js
function parse(text) {
  const eval = JSON.parse;   // 이 함수 안의 `eval`은 지역 변수다
  return eval(text);         // 전역 eval이 아니라 JSON.parse를 호출한다
}
```

`eval`이라는 이름을 변수로 쓰는 것은 sloppy script(엄격 모드가 아닌 일반 스크립트)에서만 가능하다. `'use strict'` 코드와 ES module에서는 문법 오류다.

### `eval`이라는 이름이 항상 위험한 것은 아니다

위험한 것은 **문자열을 코드로 실행하는 내장 함수(`%eval%`)**다. `eval`이라는 글자 자체가 위험한 것은 아니다. 지역 변수 `eval`이 `JSON.parse`나 직접 만든 함수를 담고 있으면, 그 호출은 코드를 실행하지 않는다. 반대로 지역 변수가 내장 eval을 담고 있으면(A8: `const eval = globalThis.eval`) 실제로 코드가 실행된다.

같은 모양의 코드라도 **변수에 무엇이 들었는지**에 따라 안전할 수도, 위험할 수도 있다. 그래서 이번에 추가한 사례는 모두 실제로 실행해 코드가 실행되지 않음을 확인했다.

### False Positive와 False Negative

| 용어 | 뜻 | 이 규칙에서의 예 | 비용 |
| --- | --- | --- | --- |
| False Positive(오탐) | 안전한 코드를 위험하다고 보고 | `let eval = JSON.parse; eval(text)`를 eval 호출로 보고 | 분석가의 시간 낭비, 경고에 대한 신뢰 하락 |
| False Negative(미탐) | 위험한 코드를 놓침 | `const eval = globalThis.eval; eval(code)`(A8)를 보고하지 않음 | 실제 위험 신호 누락 |

규칙을 고치면 둘 중 하나를 줄이다가 다른 하나를 늘리기 쉽다. 이번 테스트는 **미탐을 고치려는 변경이 오탐을 되살리는 일**을 막는다.

## 3. 기존 테스트의 빈틈

`tests/test_security_baseline.py::test_dynamic_eval_native_rule_annotations`는 `tests/fixtures/dynamic_eval_rule_test/dynamic-eval.js`에 대해 `semgrep --test`를 실행한다. `// ruleid:` 줄은 반드시 보고되어야 하고, `// ok:` 줄은 보고되면 안 된다. `todo` 주석 줄은 검사하지 않는다.

변경 전 fixture의 `ok` 사례는 다음과 같았다. `eval`/`Function` 매개변수(56, 71행), 블록 안 `const eval = JSON.parse`(63행), 재할당된 별칭(51행), 중첩 함수에서 본 바깥 바인딩(124, 133, 141행), 안쪽 별칭(151행), `policy.eval`(158행), `JSON.parse`(163행). CLI용 음성 fixture(`tests/fixtures/security_baseline/negative/dynamic.{js,ts}`)에는 `JSON.parse` 호출만 있다.

빈틈은 위험한 변형을 실제로 실행해 확인했다.

| 규칙 변형(임시, 제품 미반영) | 만드는 오탐 | 기존 fixture |
| --- | --- | --- |
| X3: `const eval = $V` 제외 삭제 | 지역 `const` 바인딩 | 실패(63, 133행) |
| **X4: `let eval = $V` 제외 삭제** | 지역 `let` 바인딩 | **통과(빈틈)** |
| CC: 두 제외 모두 삭제 | `const`·`let` 바인딩 | 실패(63, 133행) |
| **CA: 내장 eval을 담은 `const`/`let eval` 뒤 호출 재포함(P6-A 후보 A)** | 안쪽 블록 재선언, 재할당, 지역 `globalThis` | **통과(빈틈)** |
| **CB: `globalThis.eval(...)`/`window.eval(...)` 가지 추가(P6-A 후보 B)** | 지역 `globalThis`/`window` 객체 | **통과(빈틈)** |

## 4. 추가한 사례와 선택 기준

### 실행 의미 확인

후보마다 새 Node `vm` 컨텍스트(sloppy script)에서 고정 문자열 `"typeof arguments"`만 실행했다. 결과는 이렇게 읽는다.

- `"object"`: direct eval
- `"undefined"`: indirect eval
- 그 밖의 값이나 JSON 오류: 코드 실행 없음

같은 검사기를 양성 대조군(`eval(code)`, A8, `window.eval(code)`)에 돌리면 각각 DIRECT, DIRECT, INDIRECT EVAL로 보고된다. 즉 검사기는 차이를 구별한다.

| fixture 행 | 함수 | 실행 결과 | 잡아내는 변형 |
| --- | --- | --- | --- |
| 220 | `constBindingHoldsParser`: `const eval = JSON.parse` | 코드 실행 없음(JSON 오류) | X3, CC |
| 226 | `letBindingHoldsParser`: `let eval = JSON.parse` | 코드 실행 없음(JSON 오류) | **X4**, CC |
| 232 | `constBindingHoldsLocalFunction`: `const eval = (v) => v` | 코드 실행 없음(입력 그대로 반환) | X3, CC |
| 240 | `innerBlockShadowsOuterBinding`: 바깥 `const eval = globalThis.eval`, 안쪽 블록 `const eval = JSON.parse` | 코드 실행 없음 | X3, CC, **CA** |
| 248 | `letReassignedBeforeCall`: `let eval = globalThis.eval; eval = JSON.parse;` | 코드 실행 없음 | **X4**, CC, **CA** |
| 255 | `localGlobalThisBinding`: 지역 객체 `globalThis`의 `eval` 속성 | 코드 실행 없음 | X3, CC, **CA** |
| 261 | `localGlobalThisMember`: 지역 객체 `globalThis.eval(code)` | 코드 실행 없음 | **CB** |
| 267 | `localWindowMember`: 지역 객체 `window.eval(input)` | 코드 실행 없음(P6-A-R에서 Chromium으로도 확인) | **CB** |

8개 사례 모두 최소 한 개의 위험한 변형을 잡는다. 기존 213행은 한 글자도 바꾸지 않고 파일 끝에 추가했다. 그래서 기존 주석의 행 번호와 P6-A 연구 기록의 행 참조가 그대로 유지된다.

### 추가하지 않은 사례와 이유

| 사례 | 이유 |
| --- | --- |
| A8 `const eval = globalThis.eval; eval(code)`, `let` 변형 | **실제 direct eval(양성)**이다. 현재 미탐이지만 `ok`로 고정하면 미탐을 정상으로 굳힌다. 기존 `todoruleid` 기록을 그대로 둔다. |
| `eval` 매개변수, 알 수 없는 함수 반환값, 조건식, 설정값(P6-A U01~U04) | 호출자나 실행 경로에 따라 eval이 될 수도 있다. 정답이 하나로 정해지지 않는다. |
| `const eval = eval`(TDZ) | 호출 전에 `ReferenceError`로 실패하는 코드다. 실제 shadowing 사용 사례로 보기 어렵다. |
| strict 모드 A8 | 문법 오류라 실행될 수 없는 코드다. |
| `function eval`, `var eval`, 화살표 매개변수, escape 식별자 | 운영 규칙이 **현재 오탐**하는 알려진 한계다(`todook`). `ok`로 바꾸면 테스트가 실패한다. 기존 기록을 유지한다. |

## 5. 새 테스트가 실제로 막는 회귀

- `let eval` 제외를 지우거나 망가뜨리는 변경(X4)
- A8을 고치려고 "내장 eval을 담은 바인딩"을 모양으로만 다시 포함하는 변경(CA). 범위를 고려하지 않으면 안쪽 재선언, 재할당, 지역 `globalThis` 객체를 오탐한다.
- 멤버 호출 미탐을 고치려고 `globalThis.eval(...)`/`window.eval(...)`을 이름만으로 잡는 변경(CB). 지역 객체를 오탐한다.

이 테스트는 위 변경을 금지하지 않는다. 그런 변경을 하려면 **이 8개 사례를 계속 무시하도록** 설계해야 한다는 조건을 강제할 뿐이다.

## 6. 여전히 탐지할 수 없는 사례

운영 규칙은 그대로이므로 기존 미탐도 그대로다.

- A8 계열: `const`/`let eval = globalThis.eval`, `window.eval`, `globalThis["eval"]`, 두 단계 별칭, 중첩 함수에서 사용
- 멤버 호출: `globalThis.eval(code)`, `window.eval(code)`, `const e = globalThis.eval; e(code)`
- 기존 기록의 미탐: 구조 분해 별칭 일부, `Reflect.construct(Function, ...)`, closure 안 재할당 별칭, 함수 간 래퍼
- 알려진 오탐도 남아 있다: `function eval`, `var eval`, 화살표 매개변수 `eval`, escape 식별자. 모두 sloppy script 한정이다.

## 7. 검증

| 검사 | 결과 |
| --- | --- |
| 새 사례 8개 실행 의미(Node 24.22.2 `vm`) | 8개 모두 코드 실행 없음. 양성 대조군 3개는 모두 eval로 판정 |
| 변경 전 fixture: 운영 규칙 / X3 / X4 / CC / CA / CB | 통과 / 실패 / **통과** / 실패 / **통과** / **통과** |
| 변경 후 fixture: 운영 규칙 / X3 / X4 / CC / CA / CB | **통과** / 실패 / 실패 / 실패 / 실패 / 실패 |
| 운영 규칙 SHA-256 | `77d085dd4901863f8873c987f70d6ccd376ab33590724a1389885df09d5ff9df`(변경 없음) |
| CI Semgrep 통합 묶음(`SEMGREP_REQUIRED=1`, 13개 파일) | 64 passed |
| Python 전체(`SEMGREP_REQUIRED=1 pytest -q -rs`) | 681 passed, 28 skipped(Ollama·진단용 opt-in 테스트) |

### 재현 방법

```sh
# 1) 운영 규칙으로 강화된 fixture 검사 (CI와 같은 테스트)
SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q tests/test_security_baseline.py

# 2) 위험한 변형 하나를 임시로 만들어 새 테스트가 실패하는지 확인 (X4: let 제외 삭제)
T="$(mktemp -d)"
python3 - "$T/X4.yml" <<'PY'
import pathlib, sys
text = pathlib.Path("rules/security-baseline.yml").read_text()
fragment = "      - pattern-not-inside: |\n          let eval = $V;\n          ...\n"
assert text.count(fragment) == 1
pathlib.Path(sys.argv[1]).write_text(text.replace(fragment, ""))
PY
cp tests/fixtures/dynamic_eval_rule_test/dynamic-eval.js "$T"/
semgrep --test --metrics=off --disable-version-check --config "$T/X4.yml" "$T/dynamic-eval.js"
# 기대: incorrect lines: [226, 248] (변경 전 fixture에서는 통과)
```

CA·CB 변형의 정확한 규칙 텍스트는 로컬 연구 커밋 `664a765`의 `experiments/p6a-dynamic-eval/rules/CA.yml`, `CB.yml`에 있다(원격 미공개 연구 브랜치). 임시 변형 파일은 저장소에 추가하지 않았다.
