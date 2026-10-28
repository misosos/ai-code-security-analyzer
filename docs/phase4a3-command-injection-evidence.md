# Phase 4A-3 — Command Injection TaintEvidence 통합

## 요약과 범위

Phase 4A-2에서 평가한 `experimental.javascript-command-injection-taint` 규칙을 내부 TaintEvidence 신뢰 레지스트리에 등록했다. 이 변경은 experimental 규칙을 분석가 검토 파이프라인에서 검증하는 범위이며 `security-baseline.yml` 편입이나 취약점 확정이 아니다.

기준 커밋: `d07ac2e7c0017ab81cdde999209a569508b50c44`

검증 대상: Python 3.12, uv, Semgrep OSS 1.182.1

규칙 파일: `experimental/javascript-command-injection-taint.yml`
SHA-256: `abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783`

Phase 시작 전 실제 Semgrep 매치는 생성됐으나 새 규칙이 allowlist에 없어 TaintEvidence가 생성되지 않았다. Gate의 taint claim은 unavailable, Summary/Consumer 분류는 pattern, Review와 Markdown은 일반 패턴으로 표시했다. 기존 eval taint 테스트는 기존 SHA와 선언을 기준으로 정상 통과했고 baseline pattern은 taint로 승격되지 않았다.

## 신뢰 레지스트리

기존 단일 파일 경로·해시 상수를 `_TrustedRuleDeclaration` 레코드와 rule ID별 폐쇄형 레지스트리로 교체했다. 각 항목은 정확한 rule ID, 저장소 내 상대 파일 경로, 사전에 고정한 SHA-256, Source/Sink/Sanitizer 선언 요약을 한 묶음으로 가진다.

등록 항목:

| Rule ID | 상대 경로 | 고정 SHA-256 |
|---|---|---|
| `experimental.javascript-eval-taint` | `experimental/javascript-eval-taint.yml` | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | `experimental/javascript-eval-taint.yml` | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| `experimental.javascript-command-injection-taint` | `experimental/javascript-command-injection-taint.yml` | `abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783` |

Command Injection 선언은 정규화된 설명으로 기록한다. Source는 정확히 `req.query.cmd`, `req.body.cmd`; Sink 요약은 child_process module binding의 `exec`/`execSync`, named import/alias, destructured require 및 지원된 require forms와 첫 인자 focus/shadowing 조건을 보존한다. 이 문자열들은 신뢰된 해시 파일의 선언 설명이며 raw Semgrep pattern text나 실제 매치 위치가 아니다. 규칙에 `pattern-sanitizers`가 없으므로 Sanitizer 선언은 빈 tuple이다.

등록 검증은 trusted directory 내부의 strict resolve, 상대경로 일치, 일반 파일, 256,000 byte 상한, 고정 SHA-256을 요구한다. 파일 변경, 다른 rule ID/path 조합, 신뢰 디렉터리 밖 symlink는 선언을 unavailable로 처리한다. 현재 파일의 해시 일치는 Semgrep이 실행한 순간의 동일 바이트를 원자적으로 입증하지 않는다.

## 실제 Semgrep 결과와 근거 연결

SemgrepAdapter가 제한된 JSON 결과를 한 번 파싱해 기존 Finding과 TaintEvidence를 같은 result index에서 만든다. rule ID, 상대 경로, 시작 위치, Finding ID의 결정적 재계산 및 중복 ID 검사를 거친다. 각 Command Injection 결과는 `AssociationStatus.EXACT`로 연결됐다. JSON message, `extra.lines`, 코드 원문은 TaintEvidence에 복사하지 않는다.

Command Injection 관찰 결과:

- Engine: Semgrep OSS 1.182.1
- Rule ID/path/hash: registry와 일치
- Source: `req.query.cmd`, `req.body.cmd` 선언 확인
- Sink: 검증된 규칙 선언 요약 확인
- Sanitizer 선언: 없음
- match 위치: 기존 Semgrep start/end를 match location으로만 저장
- `source_location=None`, status `unknown`
- `sink_location=None`, status `unknown`
- flow trace `absent`
- sanitizer match status `unknown`

`focus-metavariable` 때문에 match가 첫 번째 명령 인자에 집중되더라도 별도 Sink argument location으로 승격하지 않는다. 실제 Semgrep JSON에 Source 위치와 구조화 trace가 없었으므로 그 경로를 재구성하지 않았다.

## Gate, Summary 및 Consumer 결과

완료된 Semgrep 1.182.1 OSS scan에서 정확히 연결되고 현재 로컬 신뢰 규칙 선언·SHA가 일치하는 Command Injection Finding은 다음 5개 claim만 supported였다.

| Claim | Decision |
|---|---|
| `MATCH_REPORTED` | supported |
| `TAINT_RULE_MATCH_REPORTED` | supported |
| `SOURCE_PATTERN_DECLARED` | supported |
| `SINK_PATTERN_DECLARED` | supported |
| `MATCH_LOCATION_OBSERVED` | supported |

나머지 claim은 원래 Gate의 제한을 보존한다. Source 위치는 `unavailable/source_location_unknown`, Sink argument 위치는 `unavailable/sink_argument_location_unknown`, trace는 `unavailable/flow_trace_absent`, sanitizer match는 선언 부재로 unavailable, sanitizer 효과와 취약점 확정은 `unsupported_claim`이다. Summary는 전체 ClaimType을 보존하고 Consumer는 소비 시점에 기존 Gate와 현재 규칙 파일을 재검증한다. 규칙 SHA 또는 Evidence 선언을 변조한 Summary 소비는 고정 오류 `evidence_consumer_rejected`로 거부됐다.

기존 eval 규칙 두 개, 합성 `syntheticSafe(...)` 선언, eval 규칙 SHA는 유지됐다. syntheticSafe는 합성 규칙 모델일 뿐 실제 Sanitizer의 안전성 검증이 아니다.

## Review 및 Markdown

등록 전 일반 pattern이던 command rule Finding은 `FindingKind.TAINT`로 표시된다. Review와 Markdown은 같은 Consumer 검증 결과와 5개 supported claim을 사용한다. 두 출력 모두 Source 위치 미제공, Sink 인자 위치 미확인, trace 부재, Sanitizer 미검증, 취약점 미확정 상태를 보존한다.

Finding ID, rule ID, severity `high`, CWE-78, 상대경로 및 line은 유지됐다. Finding은 `unverified`, confirmation은 `None`으로 남는다. 기존 CLI와 공개 JSON schema 1.0은 변경하지 않았다.

## 탐지 회귀 및 정보보호

Phase 4A-1 기존 집합은 P=9/N=9, TP=9/FP=0/FN=0/TN=9를 유지했다. Phase 4A-2 신규 집합은 P=9/N=19, TP=9/FP=0/FN=0/TN=19를 유지했다. 이는 synthetic fixture의 규칙 탐지 평가이며 실제 코드 정확도가 아니다. Phase 4A-2의 탐색 E6도 새로 지원되는 destructured require로 관찰됐다.

합성 canary를 비매칭 fixture에 넣어 Finding, Review, Markdown에 나타나지 않음을 확인했다. raw JSON, 자유 형식 메시지, 코드 원문은 출력하지 않는다. 실제 Ollama/LLM, 외부 API, Semgrep Registry/Cloud/Pro는 사용하지 않았다. OS 수준 네트워크 격리는 보장되지 않는다.

## 검증

변경 전 집중 기준선: 95 passed.

신뢰 레지스트리·Gate·Summary·Consumer·실제 Semgrep command 집중 검증: 97 passed.

기존 CI 필수 Semgrep 통합 명령(기존 integration, scan E2E, baseline, eval taint, command taint/hardening): 12 passed, 0 skipped.

전체 pytest(`SEMGREP_REQUIRED=1`): 411 passed, 28 skipped, 0 failed. Skip 28건은 기존 승인된 Ollama 평가 opt-in 테스트이며 이번 검증에서 모델 호출은 없었다.

`uv lock --check`, `git diff --check` 통과.

재현 시 Semgrep을 요구하려면 다음 환경 변수를 둔다.

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
uv run --locked python -m pytest -q -rs \
tests/test_taint_evidence.py tests/test_evidence_sufficiency.py \
tests/test_evidence_summary.py tests/test_evidence_consumer.py \
tests/test_command_injection_taint.py tests/test_command_injection_hardening.py
```

실제 모델 추론은 실행하지 않는다. 28개 Ollama 평가 테스트는 기존 opt-in skip 정책을 유지한다.
