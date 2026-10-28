# Phase 4A-1 — Node.js command injection taint PoC

## 목적과 범위

이 문서는 Semgrep OSS 1.182.1이 제한된 합성 JavaScript/TypeScript 코드에서 `req.query.cmd` 또는 `req.body.cmd`가 Node.js 명령 문자열 인자로 전달되는 정적 흐름을 보고하는지 기록한다. Ground truth는 실험 규칙의 Source→Sink 모델과 합성 코드에 한정되며, 실제 서비스의 취약점·외부 입력 도달성·악용 가능성 판정이 아니다.

신규 규칙은 `rules/experimental/javascript-command-injection-taint.yml`이며 ID는 `experimental.javascript-command-injection-taint`이다. 기존 `rules/security-baseline.yml`은 변경하지 않았다.

## Source와 Sink

Source 후보는 특정 요청 객체 이름에 제한하지 않은 `$REQ.query.cmd`와 `$REQ.body.cmd`다. 이는 요청 프레임워크, 객체 출처, 외부 요청 도달성, 검증·정제 여부를 확인하지 않는다.

Sink는 `child_process.exec()`와 `execSync()`의 첫 번째 command argument다. 옵션 객체나 callback만 tainted인 호출을 막기 위해 sink match를 `$CMD` 인자로 한정하는 `focus-metavariable`을 사용한다.

1.182.1에서 검증된 호출 모양은 다음과 같다.

- `const child_process = require("child_process")` 또는 `require("node:child_process")` 후 해당 binding의 `exec`/`execSync`
- `import * as child_process from "child_process"` 또는 `"node:child_process"` 후 해당 binding의 호출
- 직접 `require("child_process").exec(...)`, `execSync(...)`, 그리고 `node:` 대응형
- `const cp = require("child_process")` 형태의 변수 alias도 별도 탐색 사례에서 보고됐다.
- TypeScript named import fixture에서 command 입력이 named `exec`로 전달되는 흐름은 exploratory 결과에서 탐지되지 않아 지원으로 선언하지 않았다.

다음 API는 범위 밖이며, 미탐지되었다고 안전하다는 뜻이 아니다: `execFile`, `execFileSync`, `spawn`, `spawnSync`, 임의 wrapper 및 기타 shell 실행 API. `shell: true` 등 실행 옵션도 별도 검토 대상이다.

## 합성 평가

실제 입력 코드 파일만 평가 대상으로 복사한다. 테스트는 합성 파일을 임시 디렉터리에 복사해 SemgrepAdapter를 통해 한 번 검사한다. adapter의 고정 설정은 OSS 전용, 로컬 규칙, metrics/version check 비활성화, no-autofix, 60초 제한, 2MB 출력 제한이다. 샘플의 command는 정적 분석만 하며 실행하지 않는다.

Ground truth는 결과를 보기 전에 테스트에 고정했다.

| 집합 | 사례 | 기대 |
|---|---:|---|
| Positive | P1–P9, 9개 | 요청 Source가 command argument로 흐름 |
| Negative | N1–N9, 9개 | 정의된 Source→command argument 조건 불충족 |
| Exploratory | E1–E9, 파일 10개 | 범위 탐색, 혼동행렬에서 제외 |

Semgrep OSS 1.182.1 실행 결과:

| 지표 | 값 |
|---|---:|
| TP | 9 |
| FP | 0 |
| FN | 0 |
| TN | 9 |
| Precision | 9/(9+0) = 1.00 |
| Recall | 9/(9+0) = 1.00 |
| False Positive Rate | 0/(0+9) = 0.00 |

이 값은 해당 합성 fixture에만 적용된다. 오픈소스 프로젝트나 프로덕션 코드의 정확도 추정치가 아니다. 전체 결과는 11건(고정 Positive 9건, exploratory hit 2건)이며, Positive sink는 각각 Finding 한 건으로 중복 보고가 0건이었다.

탐색 집합에서 template-string command(E5)와 `const cp = require("child_process")` binding alias(E9)는 보고됐다. 함수 간 전달, 파일 간 전달, function alias, computed method, namespace import alias, named import, destructured require는 보고되지 않았다. 이 결과는 Semgrep OSS 전체 기능의 보편적 한계 증명이 아니라 이 규칙·버전·fixture의 관찰이다.

초기 sink pattern은 두 번째 인자에만 요청 값이 전달된 N6를 오탐했다. `focus-metavariable`로 command 인자만 taint sink로 지정하고, Node module import/require 문맥을 패턴에 요구한 뒤 재평가했다. 추가 대조군 N9의 일반 객체도 결과가 없었다. 평가 전 라벨은 유지했고 최종 결과에서 N6/N9는 TN이었다.

## Finding과 기존 evidence 계약

최종 Finding은 rule ID, 상대 파일 경로, match line, severity `high`(Semgrep `ERROR` 매핑), CWE-78을 보존했다. 모든 Finding은 `unverified`, `confirmation=None`이다. parser는 Semgrep 자유 형식 message와 코드 excerpt를 Finding에 복사하지 않는다.

신규 규칙은 기존 `taint_evidence.py`의 규칙 ID/SHA allowlist에 포함되지 않는다. 따라서 `_scan_with_evidence()`의 `taint_evidence`는 비어 있으며, Gate/Summary/Consumer에서는 일반 pattern Finding으로 처리된다. Review View는 새 규칙을 검증된 taint claim이라고 표시하지 않는다. 규칙 hash allowlist나 공개 API를 이번 Phase에서 변경하지 않았다.

## 제한 사항과 다음 단계

- Source pattern은 요청 입력의 실제 외부 도달성을 확인하지 않는다.
- Semgrep match는 runtime 실행, 공격 성공, 취약점 확정을 증명하지 않는다.
- module binding과 framework 설정은 정적 fixture 외 프로젝트에서 따로 확인해야 한다.
- 함수/파일 경계, function alias, namespace import의 별칭, 동적 property, named/destructured API forms는 지원 범위로 보장하지 않는다. CommonJS require의 `cp` alias는 이 fixture에서만 관찰됐다.
- OSS trace/source 위치 별도 출력이 없으므로 전체 Source→Sink path 증거를 생성하지 않는다.
- 새 규칙의 trusted Evidence 계약과 Review 분류 편입은 별도 단계에서 검증해야 한다.
- OS 수준 네트워크 격리는 제공되지 않는다. 이 평가는 외부 규칙/Cloud/Pro를 사용하지 않았지만 CLI 프로세스 자체의 OS 네트워크 차단을 보장하지 않는다.

권고: 다음 단계에서는 named import 및 module alias 지원이 실제 사용자 요구에 필요한지 먼저 결정하고, 필요할 경우 false-positive 대조군을 포함한 별도 규칙 계약 검증 후에만 Evidence allowlist 편입을 고려한다. 다른 shell APIs는 별도 규칙·fixture 평가 없이 범위에 추가하지 않는다.
