# Phase 3A-3: Semgrep OSS trace 가용성 검증

## 결론

Semgrep OSS **1.182.1**에서 `--dataflow-traces`는 `semgrep scan` 옵션으로 지원되고, `--json --oss-only`와 함께 실행도 성공했다. 그러나 공식 CLI 문서상 이 옵션은 text와 SARIF 출력에만 영향을 주며 JSON에는 적용되지 않는다. 동일 A–L 합성 fixture를 기본 JSON과 옵션 JSON으로 비교했을 때 결과는 모두 13건이고 모든 `check_id`, `path`, `start`, `end`가 같았다. 두 JSON 모두 `extra.dataflow_trace`를 포함하지 않았다.

따라서 이 단계에서 JSON 기반 TaintEvidence에 실제 Source, Sink 또는 intermediate trace 위치를 추가하지 않았다. Phase 3A-2의 위치 제한과 `flow_trace_status=absent` 동작을 유지한다.

## 공식 문서와 설치 버전 확인

Semgrep 공식 [CLI reference](https://docs.semgrep.dev/cli-reference/)는 `--dataflow-traces`를 “non-local values”의 흐름 설명 옵션으로 정의하고, text 및 SARIF 출력에만 영향을 준다고 명시한다. 공식 [taint analysis overview](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview)는 taint finding이 trace와 함께할 수 있다고 설명하지만, 실제 출력 형식과 OSS/버전 동작은 CLI 출력으로 별도 검증했다. 공식 [JSON/SARIF fields reference](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif)는 JSON `extra`의 CE 필드 목록에 `dataflow_trace`를 열거하지 않는다.

로컬 `semgrep scan --help`는 exit 0이었고 `--dataflow-traces` 항목을 포함했다. 다만 도움말을 렌더링하며 `cmdliner error: Illegal escape char` 진단도 출력했다. 별도 합성 스캔에서 `--dataflow-traces --json --oss-only` 조합은 exit 0, `engine_requested=OSS`, 결과별 `engine_kind=OSS`, `errors=[]`로 완료되어 해당 옵션 조합 자체는 실행 가능함을 확인했다. `--trace`와 tracing endpoint는 사용하지 않았다.

## 격리된 비교 실험

- 대상: Phase 3A-1 합성 A–L fixture를 임시 디렉터리에 복사한 입력
- 규칙: 신뢰된 로컬 `rules/experimental/javascript-eval-taint.yml`
- 공통 인자: JSON, OSS only, metrics off, version check off, no autofix
- 변경 변수: `--dataflow-traces` 유무
- 상한: adapter와 동일한 60초 timeout, stdout/stderr 합계 2 MB 제한
- 원본 JSON은 메모리에서만 읽고 저장·출력하지 않았다.

| 관찰 | 기본 JSON | `--dataflow-traces` JSON |
| --- | ---: | ---: |
| exit status | 0 | 0 |
| Semgrep version / engine | 1.182.1 / OSS | 1.182.1 / OSS |
| results | 13 | 13 |
| `check_id`, path, start/end 동일 | 기준 | 13/13 일치 |
| 파서가 만든 Finding ID 동일 | 기준 | 13/13 일치 |
| `extra.dataflow_trace` | 0 | 0 |
| 별도 Source 위치 구조 | 0 | 0 |
| 별도 Sink 인자 위치 구조 | 0 | 0 |
| `intermediate_vars` | 없음 | 없음 |

관찰된 start/end는 JSON의 finding match 범위다. 이 fixture에서는 `eval(...)` 호출과 위치가 겹치지만, JSON이 별도의 Sink argument location을 제공한 것은 아니다. 이 위치를 Source 또는 Sink 위치로 승격하지 않는다.

## TaintEvidence 처리

실제 JSON에 trace key가 없으면 `flow_trace_status=absent`를 유지한다. trace key가 명시적으로 빈 객체나 배열이면 `empty`, 지원되지 않는 비어 있지 않은 구조는 `unsupported`, 기대하지 않은 원시 타입은 `malformed`로 구분한다. 현재 `available` trace는 만들지 않는다. 지원하는 JSON trace schema를 확인하지 못했기 때문이다.

기존 TaintEvidence의 매치 위치, rule-file hash, Finding 연결 동작은 그대로 사용한다. Finding status는 `unverified`이며 confirmation은 생성되지 않는다. 기본 adapter 명령에 `--dataflow-traces`를 추가하지 않았다. 옵션이 JSON에서 근거를 추가하지 않기 때문이다.

## 보안 및 한계

- 합성 코드와 신뢰된 로컬 규칙만 사용했고, 모델·Cloud·Registry 요청은 하지 않았다.
- `--trace` 및 OpenTelemetry endpoint는 사용하지 않았다.
- 실행 설정은 외부 분석 연결을 요청하지 않지만 OS 수준 네트워크 차단을 제공하지는 않는다.
- help의 렌더링 진단은 관찰했으나 실제 scan 옵션 조합은 성공했다. CLI 도움말 렌더링 문제의 원인은 별도로 조사하지 않았다.
- 텍스트/SARIF 출력에서 사람이 읽는 trace가 제공되는지는 이번 JSON 계약 조사 범위 밖이다. 이를 구조화된 내부 근거로 파싱하지 않았다.

## 검증

Semgrep 전용 E2E는 `--dataflow-traces` 없는 JSON과 있는 JSON을 같은 fixture로 실행해 결과 개수와 각 Finding 위치, trace 필드 부재를 검사한다. 빈 trace 상태는 합성 JSON 단위 테스트로 검증하며, 이를 실제 Semgrep 출력이라고 주장하지 않는다. 실제 Semgrep trace 미제공은 이 버전·엔진·JSON 출력 조건에서의 관찰이다.
