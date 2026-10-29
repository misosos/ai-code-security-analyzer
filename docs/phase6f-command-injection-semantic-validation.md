# Phase 6F — Command Injection 의미 검증 및 제한적 범위 확장

## 목적과 기준

기준 커밋은 `361363bd5b9c46c976ba0599a7099eaed223c129`이며 기준 CI Run `40846609856`은 정확한 SHA의 `push / completed / success`였다. 이번 단계는 Phase 6E에서 관찰한 Command Injection 범위를 실제 Semgrep OSS 1.182.1과 새 합성 사례로 조사했다. Phase 6E Oracle 및 결과는 변경하지 않았다. 새 Phase 6F 개발 사례는 규칙 개선에 사용했으므로 독립 holdout이나 실제 운영 코드 평가로 간주하지 않는다. 독립 리뷰는 수행하지 않았다.

## CIX 사례 재현

Phase 6E의 기존 결과를 수정 전 규칙으로 다시 확인했다. CIX01과 CIX11에서 Finding이 보고됐고 CIX07, CIX08, CIX09에서는 Finding이 없었다. 다섯 사례 검사는 Semgrep OSS 1.182.1에서 `completed`, exit code 0이었다.

| 사례 | 관찰 | 해석 |
| --- | --- | --- |
| CIX11 `const cp = require("child_process")`; `cp.exec(...)` | Sink 매치가 실제 보고됨. Finding 위치는 sink 호출 행 2. | 규칙 YAML의 `child_process.exec($CMD, ...)` 구조를 Semgrep이 모듈 binding/alias 문맥에서 `cp` 호출에 연결한다. 이 Finding은 단순 텍스트의 `exec` 일치가 아니며, 같은 Source 패턴 `req.body.cmd`와 command argument taint 연결에 대한 Semgrep 보고다. 기존 평가의 `out_of_scope` 라벨은 유지한다. |
| CIX07 `spawn("tool", [req.query.cmd])` | 보고되지 않음. | Node `spawn`의 기본값은 `shell: false`다. 명령 실행 파일과 별도 argv 전달은 shell command 문자열 실행과 구분된다. 따라서 이번 CWE-78 shell-injection 규칙으로 자동 승격하지 않았다. 대상 프로그램이 인자를 해석하는 방식의 argument injection 가능성은 별도 문제이며 여기서 평가하지 않았다. |
| CIX08 helper 호출, helper 정의 없음 | 보고되지 않음. | 실제 helper가 무엇을 하는지, 명령 실행 Sink인지, 입력을 전달하는지 알 수 없어 도달성이나 실행 동작을 추측하지 않았다. |
| CIX09 `cp.exec(req.query.term)` | 보고되지 않음. | 기존 Source 계약은 `req.query.cmd`와 `req.body.cmd`로 제한된다. 다른 필드의 검토 가치는 있을 수 있지만 요청 객체 및 외부 입력 여부는 변수명만으로 증명되지 않는다. |

CIX11 Semgrep 결과에서 Finding과 TaintEvidence는 정확한 구조적 연결을 가졌다. `finding_id`, rule ID, 상대 경로와 매치 시작 행은 연결됐지만 `source_location`과 `sink_location`은 `None/unknown`, trace는 `absent`였다. 따라서 Semgrep이 `cp` 별칭을 이해했다는 관찰을 실제 Source/Sink 위치나 전체 경로 증명으로 해석하지 않는다.

Node 문서는 `spawn()`의 기본 shell 설정이 false임을 설명하며, `shell: true`일 때 shell 메타문자를 포함한 입력은 임의 명령 실행 위험을 만들 수 있다고 경고한다. 이 API 의미는 규칙 범위 선택을 뒷받침할 뿐 특정 코드의 취약점을 입증하지 않는다. [Node.js child_process 문서](https://nodejs.org/download/release/v26.8.2/docs/api/child_process.html)

## 규칙 변경

기존 `exec`/`execSync` 패턴은 유지했다. 다음의 제한된 sink 형태만 추가했다.

- `import { spawn } from "node:child_process"`에서 `spawn(command, [..., taintedArg, ...], { ..., shell: true, ... })`
- `const child_process = require("child_process")`로 얻은 모듈 binding(별칭 포함)의 `.spawn(...)`, 위와 같은 `shell: true`와 argv 원소 조건
- `import { spawn as launch } from "node:child_process"`의 `launch(taintedCommand, { ..., shell: true, ... })`

추가 패턴은 명시적인 `shell: true`를 요구한다. 기본 `spawn` 또는 `shell: false`, 옵션을 알 수 없는 경우는 추가하지 않았다. 다른 패키지의 함수, fake object, local shadowing, 정적 명령, `req.query.term`, `env` 옵션의 taint만 있는 경우를 hard-negative로 검사했다. `spawn` named import의 shadowing 대조군은 보고되지 않았다.

규칙 SHA-256은 변경 전 `abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783`, 변경 후 `a06063859bb8ce2c284412a5922fa2674679b27fbcfb3a5e12625ad430a73fb8`다. 내부 TaintEvidence 레지스트리의 고정 해시와 정규화된 sink 설명을 함께 갱신했다. Finding, Evidence, Gate/Consumer 공개 계약과 허용 claim 집합은 바꾸지 않았다. Semgrep 매치 위치 외의 Source/Sink 위치, trace 또는 sanitizer 효과를 만들어 내지 않는다.

## Phase 6F 개발 평가

사례 라벨은 최종 Semgrep 실행 전 `tests/test_command_injection_phase6f.py`에 고정했다. 총 17개 사례: Rule Signal positive 5, negative 9, out-of-scope 3. Rule Signal은 실험 규칙의 구문상 목표만을 뜻한다. Review Relevance는 별도 수동 분류이며 실제 입력 출처를 확정하지 않는다. 모든 취약점 확인은 `NOT_EVALUATED`다.

| 실행 상태 | TP | FP | FN | TN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 변경 전 규칙, 14개 점수 사례 | 2 | 0 | 3 | 9 | 1.00 | 0.40 | 0.00 |
| 변경 후 규칙, 14개 점수 사례 | 5 | 0 | 0 | 9 | 1.00 | 1.00 | 0.00 |

변경 전에는 새 `spawn(shell:true)` Positive 3개를 놓쳤고 기존 `exec` alias Positive 2개를 보고했다. 변경 후 신규 Finding 3개가 추가됐으며 이 개발 집합의 9개 Negative에서는 매치가 없었다. 3개의 out-of-scope 사례(X1 helper 경계, X2 정의 없는 helper, O1 다른 요청 필드)는 점수에서 제외했고 매치도 없었다. 중복 Finding 0건, 기대 줄 위치 불일치 0건이었다.

변경 후 보고된 5건 중 Relevance는 `review_worthy` 4건, `lower_priority` 0건, `undetermined` 1건이다. 변경 전 규칙은 P4(`exec`)와 P5의 2건을 보고했으며 각각 `review_worthy` 1건과 `undetermined` 1건이었다. 새로 탐지된 3건은 모두 `review_worthy`로 분류한 합성 사례였다. 반면 out-of-scope 집합에서 X1 helper 경계와 O1 다른 요청 필드는 `review_worthy`로 사전 분류했지만 보고되지 않았다. 이는 현재 평가 목표 바깥의 검토 범위 공백으로 기록하며 FN에는 합산하지 않는다.

같은 `req.query.cmd` 구문이 일반 로컬 객체에도 존재할 수 있음을 P5에서 확인했다. P5는 Rule Signal 기준으로는 패턴이 정의된 Source/Sink를 만족하지만 실제 HTTP 외부 입력인지 알 수 없어 Relevance를 `undetermined`로 분류했다. 따라서 이 점수는 실제 서비스 오탐률을 뜻하지 않으며, `req`라는 이름만으로 HTTP 입력을 증명할 수 없다.

## 기존 결과와 호환성

- Phase 6A–6E manifest, Oracle, 결과, 보정 기록은 수정하지 않았다.
- Phase 6E 결과를 원래 규칙으로 재현할 수 있도록 당시 규칙 파일을 `tests/benchmark/phase6e/pinned_rules/`에 SHA 고정 복사본으로 보존했다. Phase 6E evaluator는 해당 복사본을 사용하므로 결과 재현은 최신 규칙 점수화와 혼동되지 않는다.
- Command Injection 신뢰 레지스트리 해시만 현재 규칙 바이트에 맞게 변경했다. Eval, baseline 및 Firestore 규칙은 변경하지 않았다.
- Finding 상태는 `unverified`, severity `high`, CWE 메타데이터 `CWE-78`로 유지된다. 이 값들은 취약점 확정이 아니다.
- 새 규칙은 experimental 디렉터리에 남고 baseline에는 편입되지 않았다.

## 검증 결과와 한계

Semgrep OSS 1.182.1 실제 실행에서 Phase 6F 점수 사례는 변경 전후 모두 completed였다. 새 통합 테스트는 Rule ID, severity/CWE, 상대 경로, 행, 중복, canary 비노출, Finding 상태 및 TaintEvidence consumer가 기존 다섯 supported claim만 허용하고 위치·trace를 미확인 상태로 남기는지를 검사한다.

실제 Express 실행, 라우트 등록, 입력 도달성, 런타임 검증/정제, Node 버전별 shell 동작, 운영체제별 동작, 사용자 명령의 영향, 실제 취약점은 검증하지 않았다. 옵션 객체가 변수·helper로 만들어지는 형태, 다른 `spawn` import, 동적 옵션, 함수 간·파일 간 흐름, `execFile` 계열, 일반 argument injection은 지원 완료라고 주장하지 않는다. Semgrep `shell: true` 패턴도 runtime binding 불변성이나 실제 OS 실행을 보증하지 않는다.

## 다음 검토 과제

1. `req` 식별자 기반 Source를 넓히기보다, 요청 경로를 명시적으로 모델링하는 안전한 규칙 표현을 별도 평가한다.
2. `shell: true` 옵션의 변수 전달/구성 형태는 지원 범위를 섣불리 넓히지 말고 hard-negative와 독립된 미사용 검증 사례를 준비한다.
3. `spawn`의 shell injection과 target-specific argument injection을 다른 분류·규칙 목표로 유지한다.
4. 이 Phase 6F 개발 집합은 규칙 변경에 사용됐으므로 향후 성능 주장에는 새 독립 평가 데이터가 필요하다.
