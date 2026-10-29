# Phase 6I — Semgrep Taint Trace 근거 가능성 및 출처 검증

## 범위 및 시작 Gate

목표는 Semgrep OSS 1.182.1이 제공하는 실제 taint Source/Sink 위치와 흐름 trace를 합성 코드에서 확인하는 것이다. 규칙·분석기·TaintEvidence 신뢰 계약은 변경하지 않았다.

- 저장소: `misosos/ai-code-security-analyzer`
- 기준 SHA: `b657b8fea8b8798ff7dbd68251f7b044a35b5dcb`
- 시작 branch: `main`; HEAD, `origin/main`, 원격 `main` 모두 기준 SHA
- 시작 작업 트리: clean; ahead 0 / behind 0
- Semgrep OSS: 1.182.1
- 기준 GitHub Actions Run `40869484855`: 기준 SHA의 `push / completed / success`
- Python, Semgrep, React/Chromium 및 실제 Chromium–FastAPI–Semgrep E2E 단계: 모두 성공

기존 평가 및 규칙 SHA-256을 시작 Gate에서 확인했다. 대표값은 eval-taint 규칙 `6c0274e4…ad8e8e`, command-injection 규칙 `a0606385…0a73fb8`, baseline `bfeb93c4…fc70a1a3`, Phase 6E manifest `0aa7c9eb…5e005c24`, Oracle `b62dd1b9…b2b54fb`였다. Phase 6H source-context 규칙은 `ad3d1515…794773d1`이다. 이번 작업은 이 파일들을 수정하지 않았다.

## CLI 옵션과 실제 OSS 관찰

Semgrep 1.182.1의 `semgrep scan --help`에는 `--dataflow-traces`가 있다. 도움말은 이 옵션을 text 및 SARIF 출력에 한정해 설명한다. JSON과 SARIF에 모두 옵션을 적용해 실측했다. 규칙은 신뢰된 로컬 eval-taint, command-injection, source-context 파일만 지정했고 `--oss-only`, `--no-autofix`, metrics off, version check off를 사용했다. 각 실행에는 기존 공통 60초 timeout 및 2,000,000-byte stdout 상한을 적용했다. 외부 Registry/Cloud/Pro 엔진은 사용하지 않았다.

`tests/fixtures/taint_trace_phase6i/`의 21개 고정 합성 사례와 테스트 실행 중 임시 생성한 privacy canary 사례를 대상으로 JSON plain, JSON `--dataflow-traces`, SARIF `--dataflow-traces`를 비교했다. 원본 결과는 테스트 프로세스 메모리에서만 처리했고 파일·로그·보고서에 저장하지 않았다.

| 출력 형식 | Finding 수 | Trace 상태 | Trace 관련 위치/흐름 정보 |
| --- | ---: | --- | --- |
| JSON, 옵션 없음 | 26 | 비교 기준 | 없음 |
| JSON, `--dataflow-traces` | 26 | absent 26 | 결과의 `dataflow_trace`/`taint_trace`/`trace` 키와 trace 관련 `extra` 키 없음 |
| SARIF, `--dataflow-traces` | 26 | `codeFlows` absent 26 | `threadFlows` 및 `threadFlowLocations` 없음 |

JSON 옵션 유무와 SARIF의 정규화된 Finding 집합은 Rule ID, 상대 경로, start/end 좌표 기준으로 모두 일치했다. Trace 자체는 한 건도 나오지 않았다. 따라서 trace가 전체/부분/대표 trace 중 무엇인지 분류할 수 없으며, complete trace는 **NOT_VERIFIED**다. 이 OSS 실행에서 trace 위치 schema 자체가 관찰되지 않았다.

## 합성 사례 및 Finding 연결

신규 개발 corpus 버전은 `phase6i-trace-feasibility-dev-v1`이고 manifest SHA-256은 `ba5214f5e6465907ef61450fe180530e9b79acef8d54113f8a11fc6ae2e7d805`다. 데이터는 직접 작성한 합성 코드이며 일반화 벤치마크가 아니다. 취약점 확인은 모두 `NOT_EVALUATED`다.

21개 사례는 Eval 13개와 command execution 8개로 구성했다. 직접·다중 줄·변수 할당·복수 Source·복수 Sink, source-only/sink-only, 일반 객체, Express route, synthetic sanitizer 모델, `exec`/`execSync`, named import alias, `spawn`의 `shell: true/false`, 단절 흐름 및 함수 경계를 포함한다. C02의 `cp = require("node:child_process")` 별칭은 실제 실행에서 현재 규칙 Finding이 없었다. 이는 규칙에 명시된 바인딩 형태를 벗어나므로 out-of-scope로 기록했고, 원래의 기대 변경과 이유를 manifest `oracle_revision_history`에 남겼다. 해당 코드를 negative나 안전 사례로 바꾸지 않았다.

고정된 점수 집합은 Rule Signal positive 13, negative 6, out-of-scope 2였다. 관찰된 case-level 값은 TP=13, FP=0, FN=0, TN=6 (Precision 1.00, Recall 1.00, FPR 0.00)이다. 이는 작은 개발용 구문 사례에서 기대한 규칙 신호를 확인한 값일 뿐 취약점 Precision/Recall이 아니다. Out-of-scope 사례는 혼동 행렬에 포함하지 않았다.

실제 26개 Finding의 규칙별 건수:

| Rule ID | Finding 수 |
| --- | ---: |
| `experimental.javascript-eval-taint` | 11 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 10 |
| `experimental.javascript-command-injection-taint` | 4 |
| `experimental.javascript-eval-source-context` | 1 |

검증 결과 26/26의 match file과 시작·종료 좌표가 유효했고, JSON parser가 생성한 Finding ID와 Rule ID/상대 경로/start/end가 같은 결과 인덱스에서 일치했다. JSON과 SARIF 간 정규화된 위치도 26/26 일치했다. 중복 signature 0, 잘못되거나 범위 밖 위치 0이었다. 이것은 **Semgrep match 위치와 Finding의 연결** 검증이다. Source/Sink 위치와 trace를 Finding에 연결한 결과는 0건이며, trace 부재로 그러한 연결 자체를 수행할 수 없었다.

## Source/Sink provenance와 기존 계약

이번 측정에서 구조적으로 확인된 것은 Semgrep이 보고한 match 위치뿐이다. Source 패턴 선언과 Semgrep match line은 실제 Source 위치와 다르다. match 위치를 Sink 인자 위치로 추정하지 않았다.

기존 `TaintEvidence` 정책을 유지한다.

- `source_location=None`, 상태 `unknown`
- `sink_location=None`, 상태 `unknown`
- 실제 trace 미제공: `flow_trace_status=absent`
- Finding 상태 `unverified`; 취약점 확인 생성 없음
- Source 위치, Sink 인자 위치, 전체 흐름 및 런타임 HTTP 입력 도달성: 확인되지 않음

코드상 Express route callback이 관찰돼도 이는 구조적 문맥이다. 실제 server mount, 요청 도달성, 외부 사용자 제어 여부는 증명하지 않는다. Semgrep이 trace 한 개를 제공하는 경우에도 그것이 모든 가능한 경로를 포괄한다고 자동으로 해석할 수 없다.

## Trace 정규화와 개인정보

운영용 또는 내부 실험용 trace 추출기는 구현하지 않았다. trace field가 absent였고 OSS trace schema를 검증할 자료가 없으므로 좌표 추출을 시도하지 않는 것이 적절했다. 기존 `taint_evidence.py`는 비어 있는 trace, 잘못된 scalar, 인식하지 못하는 비어 있지 않은 구조를 각각 empty/malformed/unsupported로 구분하며, 값을 Evidence에 보관하지 않는다. 기존 테스트는 중복 Finding, 잘못된 좌표, path traversal, 불명확한 연결 및 synthetic canary 비노출도 검증한다.

Phase 6I 테스트는 임시 합성 파일에만 privacy canary를 넣고, 결과 요약에는 상태·규칙 ID·상대 경로·좌표·카운트만 남긴다. canary 문자열, 코드 excerpt, 자유 형식 메시지, 절대 경로 또는 raw JSON/SARIF는 보고서·JUnit 결과에 포함하지 않는다. OS 수준 네트워크 차단을 제공했다고 주장하지 않는다.

## 변경 및 검증

- 신규 평가 fixture와 실제 Semgrep JSON/SARIF trace 실험 테스트를 추가했다.
- CI의 필수 Semgrep integration 단계에 `tests/test_taint_trace_phase6i.py`를 추가했다.
- 규칙, Adapter 기본 실행 인자, parser, Finding/TaintEvidence 공개 계약, Gate/Consumer, API/CLI/React 및 dependency/lockfile은 변경하지 않았다.
- `--dataflow-traces`를 포함한 실제 합성 스캔에서 Semgrep 1.182.1의 결과는 completed/exit 0, 26 Finding이었다. 출력은 2MB 제한 내였고 60초 timeout도 발생하지 않았다.

Trace Feasibility 판정은 **`PHASE_6I_TRACE_EVIDENCE_UNSUPPORTED`**다. 해당 Semgrep OSS 버전과 평가한 규칙/fixture 조합에서는 JSON trace 필드와 SARIF `codeFlows`가 제공되지 않았다. Finding match 좌표와 ID의 구조적 연결은 확인됐지만 Source/Sink 좌표는 0건이다. 이는 다른 Semgrep 버전·엔진·모든 규칙에 대한 보편적 부재 주장은 아니다.

후속 단계에서는 별도 버전이나 출력 모드가 OSS 범위 안에서 구조화 trace를 제공하는지 다시 검증할 수 있다. 그때도 먼저 schema, 경로·좌표, 동일 Finding 연결, 개인정보 제거를 독립 검증하고, 운영 TaintEvidence 승격은 별도 승인·회귀 단계로 둔다.

## Phase 6I 로컬 회귀

- `uv lock --check`: 통과
- `uv sync --locked --dev`: 통과
- 전체 Python: `532 passed, 28 skipped, 0 failed`; Starlette TestClient anyio alias deprecation 경고 1건
- Phase 6I 전용 실 Semgrep 통합: `2 passed`
- Frontend typecheck: 통과
- Vitest: `24 passed`
- Frontend build: 통과
- Chromium mock/browser tests: `3 passed`
- 실제 `npm run test:e2e:real`: `1 passed`; Chromium → FastAPI → Semgrep 1.182.1 → Evidence 응답 경로 확인
- `git diff --check`: 통과

테스트는 실제 사용자 저장소나 credential을 사용하지 않았다. 실제 브라우저 E2E는 프로젝트의 격리 스크립트가 생성한 임시 합성 target/rules와 난수 토큰을 사용했고 종료 후 임시 데이터를 정리했다. 이 run에 대한 원격 GitHub Actions는 commit/push하지 않았으므로 실행되지 않았다. 기준 CI 성공과 이번 로컬 검증은 별개다.
