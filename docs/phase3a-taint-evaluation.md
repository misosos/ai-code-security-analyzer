# Phase 3A-1: Semgrep OSS taint PoC 평가

## 범위와 공식 기능 기준

실험은 2026-10-28 로컬 Semgrep 1.182.1에서 실행했다. `SemgrepAdapter`의 신뢰 규칙 디렉터리 아래 `rules/experimental/javascript-eval-taint.yml`만 추가했다. 기존 baseline 파일은 수정하지 않았다. 새 규칙은 `req.query.code`와 `req.body.code`를 패턴 source로, `eval`의 첫 인자를 sink로 정의한다. 별도 규칙은 같은 정의에 `syntheticSafe($VALUE)` 패턴만 sanitizer로 추가해 결과 차이를 비교한다.

Semgrep 공식 규칙 문서는 `mode: taint`, `pattern-sources`, `pattern-sinks`, `pattern-sanitizers`로 source/sink/sanitizer 패턴을 정의하는 방식을 설명한다. [Taint mode 안내](https://semgrep.dev/blog/2022/demystifying-taint-mode/)는 변수 전달 및 sanitizer 모델링을 예시로 든다. [공식 glossary](https://semgrep.dev/docs/writing-rules/glossary)는 Semgrep CE/OSS를 per-file 분석으로 한정하고, cross-file 분석은 proprietary 엔진 기능이라고 구분한다. 여기서 지원되는 범위는 문서 일반 설명만으로 단정하지 않고 1.182.1 `--oss-only` 실행 결과로 검증했다.

## 합성 사례와 관찰

13개 합성 파일에 A–L 사례를 구성했다(J는 source/sink 두 파일). `source`와 `sink`의 줄은 fixture 안의 코드 위치이며, 사용자 입력 도달성이나 실제 공격 성립을 뜻하지 않는다.

| 사례 | source 위치 | sink 위치 | Taint 기대 | 실제 OSS taint 관찰 | 설명 |
| --- | --- | --- | --- | --- | --- |
| A direct | `A_direct.js:2` | `:2` | 탐지 | plain·modeled 모두 탐지 | 직접 전달 |
| B assignment | `B_assignment.js:2` | `:3` | 탐지 | 둘 다 탐지 | 단일 변수 할당 |
| C multistep | `C_multistep.ts:2` | `:5` | 탐지 | 둘 다 탐지 | 다단계 변수 전달 |
| D constant | 없음 | `D_constant.js:3` | 미탐 | 둘 다 미탐 | 상수만 sink에 전달 |
| E unrelated | `E_unrelated.js:2` | `:4` | 미탐 | 둘 다 미탐 | source와 sink 입력이 무관 |
| F unknown sanitizer | `F_unknown_sanitizer.ts:2` | `:3` | 탐지 | 둘 다 탐지 | 이름만 검증처럼 보이는 함수는 sanitizer 아님 |
| G modeled sanitizer | `G_modeled_sanitizer.js:2` | `:3` | plain 탐지, modeled 규칙 미탐 | plain만 탐지 | `syntheticSafe`가 sanitizer라고 가정한 규칙 효과 |
| H partial condition | `H_partial_condition.js:2` | `:4` | 탐지 | 둘 다 탐지 | 길이 조건이 정제라고 모델링되지 않음 |
| I function boundary | `I_function_boundary.js:2` | `:6` | 범위 미보장 | 미탐 | helper 반환과 별도 sink 함수 사이 흐름 |
| J split file | `J_split_source.js:2` | `J_split_sink.js:2` | 범위 미보장 | 미탐 | source/sink가 파일 분리 |
| K nested TS | `K_nested_conditions.ts:4` | `:8` | 탐지 | 둘 다 탐지 | 타입 주석·중첩 조건·변수 대입 |
| L comment/string | 없음 | 실제 sink 없음 | 미탐 | 미탐 | 위험 구문 모양이 주석·문자열에만 존재 |

### 규칙별 결과

| 실행 | 탐지 수 | 결과 위치/규칙 | 해석 |
| --- | ---: | --- | --- |
| 기존 `baseline.javascript-dynamic-eval` | 11 | A–H, I sink, J sink, K | 실제 `eval` 호출을 source와 무관하게 잡음. D 상수·E 무관 source도 후보로 보고 |
| `experimental.javascript-eval-taint` | 7 | A, B, C, F, G, H, K | 정의한 source→sink 패턴을 in-scope 사례에서 탐지 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 6 | A, B, C, F, H, K | G의 해당 패턴만 sanitizer로 취급해 억제 |

지원 범위 10개(A–H, K, L)의 미리 정한 합성 흐름 라벨에 한정하면 plain taint는 TP=7, FP=0, FN=0, TN=3이다. Sanitizer 모델 규칙은 규칙이 의도한 결과 라벨 기준 TP=6, FP=0, FN=0, TN=4다. 이 두 번째 집계에서 G의 TN은 `syntheticSafe`가 실제로 안전하다는 뜻이 아니라, 규칙에 인코딩한 sanitizer 가정에 맞게 경고가 억제됐다는 의미다. I/J 두 사례는 OSS 엔진의 함수 간·파일 간 분석 범위를 평가한 별도 범주로 모두 표시했고, 이들에 대한 성능 라벨을 억지로 부여하지 않았다.

Baseline은 source→sink 분석 규칙이 아니다. 같은 10개 in-scope를 flow 라벨로만 사후 비교하면 A/B/C/F/G/H/K 일치 7건, 상수 D 및 무관 source E의 추가 sink 경고 2건, L 비경고 1건이다(TP=7, FP=2, FN=0, TN=1). 이 2건은 baseline의 목적(위험 API 사용 위치 검토)을 벗어나 taint 목적에 대입했을 때의 차이이며 baseline 자체의 취약점 오탐률로 해석하지 않는다. I/J에서는 baseline이 sink 위치를 찾아도 source→sink 관계를 입증하지 않는다.

## Semgrep 1.182.1 JSON과 Finding 근거

실제 CLI는 `--json --metrics=off --disable-version-check --oss-only --no-autofix`와 신뢰된 로컬 규칙만 사용했다. 원시 JSON은 13개 합성 파일을 스캔했고 top-level `engine_requested`는 `OSS`, 버전은 `1.182.1`, `errors`는 빈 배열이었다. 13개 taint 결과의 `extra.engine_kind`도 모두 `OSS`였다. 각 결과에는 `check_id`, 절대 파일 경로, `start`/`end` 위치 및 `extra`가 있었다.

관찰한 `extra` key는 `engine_kind`, `fingerprint`, `lines`, `message`, `metadata`, `severity`, `validation_state`였다. 이 1.182.1 OSS JSON에서는 `dataflow_trace`와 `metavars`가 결과에 없었고 별도 source 위치도 제공되지 않았다. `start`/`end`는 sink 매치 위치를 제공하고 `extra.lines`는 sink 주변 매치 텍스트를 포함했다. 따라서 source 위치부터 sink까지 이어지는 trace를 만들어내거나 이를 Finding에 넣지 않았다. 현재 parser는 raw `message`/코드 조각을 public Finding에 복사하지 않고 결과는 `unverified`, severity `high`, CWE-95로 변환됐다. 합성 canary는 공개 Finding 및 repr에 포함되지 않음을 테스트했다.

trace가 제공되면 그 형식과 모든 source/sink 지점을 검증한 뒤 별도 계약을 설계할 수 있다. 이번 출력에서는 trace가 없으므로 내부 `TaintEvidence`를 채우지 않았고, 실제로 증명된 정보만 기록했다.

## Sanitizer의 신뢰 한계

Semgrep sanitizer 설정은 패턴 일치 코드를 taint-clean으로 취급하게 하는 분석 지시다. 함수 이름이 `sanitize`, `validate`이거나 조건문이 존재한다는 이유만으로 보안상 유효한 정제를 검증하지 않는다. 실험용 `syntheticSafe`는 합성 위협 모델에 명시된 단일 패턴만 규칙에서 신뢰했다. F의 `unknownValidate`와 H의 길이 조건은 그대로 taint를 전달했다. 결과 억제는 sanitizer 패턴 모델의 영향이며 안전 증명이 아니다.

## 보안 및 재현성

- fixture는 테스트 실행 시 임시 디렉터리에 복사했고 코드 실행은 하지 않았다.
- 규칙은 저장소의 신뢰된 `rules/` 아래 명시적 로컬 파일이며 Registry/원격 규칙을 사용하지 않았다.
- adapter와 raw JSON 테스트 모두 OSS, metrics off, version check off, autofix off를 적용했다. raw 테스트는 adapter와 같은 60초 제한·2 MB 출력 상한·임시 HOME을 사용한다.
- raw JSON은 메모리에서 구조만 검사하고 출력·파일 저장하지 않는다. 테스트는 합성 canary가 공개 Finding으로 유출되지 않는지 확인한다.
- adapter는 기존 Finding 계약, timeout, 출력 제한을 유지한다. 테스트에서 모든 taint Finding은 `unverified`이고 confirmation이 없다.
- 분석기와 CI는 OS 수준 네트워크 격리를 제공하지 않는다. 원격 설정·Cloud·metrics를 요청하지 않는 것과 OS 네트워크 차단은 별개의 보장이다.

## 테스트와 CI

로컬 실행 명령:

```sh
uv run --locked python -m pytest -q -rs tests/test_semgrep_taint_evaluation.py
```

`tests/test_semgrep_taint_evaluation.py`는 Semgrep 설치를 요구하고, 설치돼 있으면 정확히 1.182.1인지 검사한다. Semgrep이 없는 일반 Python job에서는 skip되지만, `.github/workflows/ci.yml`의 Semgrep 전용 job은 `SEMGREP_REQUIRED=1`로 실행해 누락/skip을 실패 처리한다. CI는 기존 pinned Semgrep 1.182.1 설치·버전 확인 및 local-rule 테스트를 유지하며 이 테스트 파일만 추가했다. Ollama와 LLM 평가는 추가하지 않았다.

실행 결과(2026-10-28): `uv run --locked python -m pytest -q -rs tests/test_semgrep_taint_evaluation.py`는 1 passed, 0 skipped였고, CI Semgrep 전용 테스트 집합은 5 passed, 0 skipped였다. 전체 `pytest -q -rs`는 231 passed, 28 skipped, 0 failed였다. skip은 기존 opt-in LLM 평가들이다. 이 작은 합성 set의 TP/FP/FN/TN은 실제 앱 취약점 정확도 추정치가 아니다.
