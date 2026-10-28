# Phase 4A-2 — Command Injection Rule Hardening 평가

## 목적과 판정 범위

이 평가는 실험 규칙 `experimental.javascript-command-injection-taint`의 import/require 범위와 오탐 저항성을 Semgrep OSS 1.182.1에서 합성 JavaScript/TypeScript로 확인한다. 결과는 고정된 Source→첫 번째 command argument 실험 목표에 한정되며 실제 서비스의 취약점 판정이 아니다. 기존 baseline과 TaintEvidence allowlist는 바꾸지 않았다.

## 재현 환경

- 기준 커밋 및 변경 전 기준: `00722addbedeb619b034ba43fed8a351006bfdb7`
- Python 3.12 / uv / Semgrep OSS 1.182.1
- 규칙: `rules/experimental/javascript-command-injection-taint.yml`
- 입력은 저장소의 합성 fixture를 임시 디렉터리에 복사한 코드다. 명령 실행 코드는 실행하지 않았다.
- adapter의 OSS 전용, 로컬 규칙, no-autofix, 60초 timeout, 2 MiB 출력 한도, metrics/version check 비활성화 설정을 유지했다.

재현 명령:

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
uv run --locked python -m pytest -q -rs \
tests/test_command_injection_taint.py \
tests/test_command_injection_hardening.py
```

## Phase 4A-1 기준선 동결

규칙을 변경하기 전에 기존 `tests/test_command_injection_taint.py`를 실행해 고정 기준을 재현했다. P1–P9 9개, N1–N9 9개에서 TP=9, FP=0, FN=0, TN=9였고, exploratory 결과는 E5 template-string과 E9 CommonJS binding alias 두 건이었다(총 11 Finding). 규칙 변경 뒤에도 기존 P/N 결과는 동일했다. 신규 destructured require 지원으로 exploratory E6가 추가 매칭되어 관찰 집합은 E5, E6, E9 세 건(총 12 Finding)이 됐다. 이는 P/N 회귀가 아니라 탐색 범위의 확장이다.

## 평가 집합과 사전 라벨

P/N 라벨은 결과 확인 전에 테스트에 고정했다. 라벨은 이번 규칙의 명시된 모듈·Source·Sink 조건만 뜻한다.

| 집합 | 사례 | 수 | Ground truth |
|---|---|---:|---|
| 기존 기준선 | P1–P9 / N1–N9 | 9 / 9 | Phase 4A-1 고정 사례 |
| 신규 Positive | P10–P18 | 9 | `req.query.cmd` 또는 `req.body.cmd`가 실제 child_process 명령 첫 인자로 전달 |
| 신규 Hard Negative | N10–N28 | 19 | 규칙의 모듈·Source·첫 인자 흐름 조건을 만족하지 않음 |
| 탐색 | X1–X10 (X2는 두 파일) | 11 파일 | 지원 범위 관찰용, 혼동행렬에서 제외 |

Negative 라벨은 코드가 안전하다는 뜻이 아니다. 해당 사례가 이 규칙의 사전 정의 탐지 목표가 아니라는 뜻이다.

## 규칙 변경 전후

수정 전 신규 P10–P18/N10–N28 집합에서는 P16, P17, P18만 탐지됐고 N14와 N26도 매칭됐다. 고정 라벨 기준 TP=3, FP=2, FN=6, TN=17이었다.

오탐 원인과 조치:

- N14: 함수 안에서 `child_process` 이름이 다른 객체로 shadow됐는데 외부 require 문맥을 sink 호출에 잘못 적용했다. require 기반 패턴에 함수 로컬 shadowing 제외를 추가했다.
- N26: `$REQ.query.cmd` Source가 서로 다른 임의 객체명도 Source로 처리했다. Source를 정확한 `req.query.cmd` 및 `req.body.cmd`로 제한했다. 다른 request 변수명을 쓰는 입력은 놓칠 수 있다.

Named import/alias와 destructured require/alias 패턴을 명시적 모듈 문맥에 묶어 추가했다. Sink는 계속 첫 번째 명령 인자에만 focus된다. 수정 후 신규 집합 결과는 TP=9, FP=0, FN=0, TN=19였다.

| 집합/버전 | TP | FP | FN | TN | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| 신규 P/N, 변경 전 | 3 | 2 | 6 | 17 | 0.60 | 0.3333 | 0.1053 |
| 신규 P/N, 변경 후 | 9 | 0 | 0 | 19 | 1.00 | 1.00 | 0.00 |
| 기존 P/N, 변경 후 | 9 | 0 | 0 | 9 | 1.00 | 1.00 | 0.00 |

수치는 각각 9·19 또는 9·9개의 합성 사례 단위 결과이며 실제 코드 정확도 추정이 아니다. 신규 fixture의 최종 결과는 12건: Positive 9건과 exploratory X8, X9, X10 각 1건이다. P 사례당 중복 Finding은 없었고, X10의 두 sink 중 tainted command가 있는 매치 하나만 나왔다.

## 확인된 import/require 지원 범위

P10–P15는 모두 실제 Semgrep 결과가 있었다.

- `node:child_process`의 named import `exec` 및 `execSync`
- Named import alias `exec as runCommand`
- `require("child_process")`의 destructured `exec`/`execSync`
- `require("node:child_process")`의 destructured alias `exec: runCommand`
- 기존 직접 require, namespace import, `cp = require(...)` module variable 형태

이는 현재 규칙과 해당 합성 fixture에서 관찰된 호출 형태다. 모든 번들러, alias, 런타임 호출 문맥을 보장하지 않는다.

| 관찰 구분 | 사례 | 결과 |
|---|---|---|
| 현재 규칙에서 탐지 | P10–P18 | 9건, 각 1 Finding |
| 안전한 제한 확장 후 탐지 | P10–P15 | named/destructured import 패턴 |
| FP 위험으로 제한 | 임의 요청 객체 Source, shadowed `child_process` | 정확한 `req` Source 및 shadow 제외 |
| 현재 fixture에서 미관찰 | X1–X7 | 함수/파일 간, method alias, computed access, dynamic require, 변경 참조, helper 반환은 결과 없음 |
| 탐색 결과로 관찰 | X8–X10 | complex template, 조건 분기, 복수 sink 중 tainted 흐름 각 1건 |

X1–X7은 이 규칙·버전·fixture 조합에서 지원이 확인되지 않았다는 뜻이며 Semgrep OSS 전체 기능의 보편적 한계 증명은 아니다.

## Hard-negative와 sink 경계

N10–N28은 모두 미탐(규칙의 기대 결과)이었다. 사례에는 plain object/RegExp/mock/fake/local `exec`, shadowing, 다른 패키지 import, 옵션 또는 callback 인자에만 taint가 있는 호출, 상수 명령, 문자열 처리, 비슷한 모듈 이름, 진짜/가짜 호출 혼합, 재할당된 module, 다른 request object, 끊긴 데이터 흐름이 포함된다.

N6(기존 집합) 및 N18/N19(신규 집합)에서 옵션·callback 인자에만 입력이 있으면 매칭되지 않았다. 따라서 `focus-metavariable`의 첫 번째 command argument 경계가 유지됐다. N14와 N26의 수정 전 false match도 사라졌다. N24의 혼합 사례에서 가짜 객체 호출은 추가 매칭되지 않았다.

N25의 모듈 참조 재할당은 현재 fixture에서 매칭되지 않았다. 패턴 문맥이 모든 런타임 binding 변경을 증명하거나 배제한다고 주장하지 않는다.

## 탐색 결과

X8 complex template, X9 conditional branch, X10 multiple sinks가 관찰됐다. X10은 tainted command가 있는 sink 하나만 매칭했다. X1 interprocedural, X2 interfile, X3 method alias, X4 computed property, X5 dynamic require, X6 mutated reference, X7 helper return은 결과가 없었다.

이는 엔진 전체 기능에 대한 결론이 아니다. `execFile`, `execFileSync`, `spawn`, `spawnSync`는 범위 밖이며 탐지되지 않았다고 안전한 것으로 판정하지 않는다.

## 근거 계약, CLI 및 정보보호

- 규칙 ID `experimental.javascript-command-injection-taint` 유지.
- 신규 규칙은 기존 TaintEvidence 신뢰 목록과 SHA allowlist에 편입되지 않았다. `_scan_with_evidence`의 TaintEvidence는 비어 있다.
- Gate/Consumer/Review는 새 규칙을 trusted taint claim으로 승인하지 않고 일반 pattern Finding으로 처리한다. Review와 Markdown은 검증된 taint claim 문구를 출력하지 않는다.
- Finding ID, 상대 경로, 위치, severity `high`, CWE-78을 확인했다. Finding은 모두 `unverified`, confirmation 없음이다.
- 기존 CLI text/json/review/review-md 및 공개 JSON 계약은 변경하지 않았다.
- 합성 canary를 비매칭 코드 주석에 넣고 Finding/Review/Markdown 출력에 나타나지 않는지 확인했다. 원본 코드·raw JSON·자유 형식 Semgrep 메시지는 출력 모델에 복사하지 않는다.
- Ollama/LLM, 모델 다운로드, Registry, Cloud, Pro는 사용하지 않았다.

## 검증 결과와 CI

필수 Semgrep 검증은 Semgrep 미설치 시 실패하도록 `SEMGREP_REQUIRED=1`로 실행한다. Semgrep 전용 GitHub Actions 단계에 신규 `tests/test_command_injection_hardening.py`를 추가했다. 실제 실행은 5 passed, 0 skipped였다. 전체 회귀 결과는 최종 검증 후 이 문서 및 최종 보고에 반영한다.

## 한계와 4A-3 권고

- Source는 정확히 `req` 이름으로 제한되어 다른 framework/request 변수명을 놓칠 수 있다.
- 모듈 문맥 패턴은 런타임 import binding, 동적 재할당, 프레임워크 도달성, 배포 구성을 완전히 증명하지 않는다.
- Semgrep JSON에는 별도 Source 위치, Sink argument 위치, 전체 trace가 없다. match 위치를 그 근거로 승격하지 않았다.
- CWE-78 및 taint rule match는 검토 후보이지 공격 성공 또는 취약점 확정이 아니다.
- 외부 Registry/Cloud를 사용하지 않았지만 OS 수준 네트워크 격리는 보장되지 않는다.

4A-3에서 trusted TaintEvidence allowlist 편입을 검토하려면 규칙 hash와 provenance, 실제 Semgrep 결과와 Evidence 연결, Pattern에서 trusted taint 분류로의 전환을 별도 검증해야 한다. Source 위치와 trace 부재를 계속 표시하고 Finding `unverified`를 유지해야 한다. 이번 결과만으로 baseline 또는 신뢰 근거로 자동 승격하지 않는다.
