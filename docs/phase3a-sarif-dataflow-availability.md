# Phase 3A-4: Semgrep OSS SARIF Dataflow Evidence 가용성

## 결론

Semgrep OSS 1.182.1은 로컬 taint 규칙 실행 결과를 SARIF 2.1.0으로 출력했다. 합성 A–L fixture에서 JSON, 기본 SARIF, `--dataflow-traces` SARIF 모두 결과 13건을 보고했다. SARIF의 규칙 ID, 대상 파일, 시작·종료 줄과 열을 JSON 결과와 대조했을 때 각 SARIF 실행은 13/13 일대일 대응했고 중복 또는 모호한 위치 서명은 없었다.

두 SARIF 실행 모두 13개 result에서 `codeFlows` 필드가 없었다. 따라서 `threadFlows`와 `threadFlowLocations`도 관찰되지 않았고, 별도의 Source 위치, Sink 인자 위치, 중간 전달 위치를 얻지 못했다. `--dataflow-traces`는 이 조건에서 SARIF의 흐름 구조를 추가하지 않았다. TaintEvidence 계약과 생산 adapter는 변경하지 않으며, Source/Sink 위치는 계속 unknown, trace 상태는 absent로 유지한다.

이 결과는 해당 합성 fixture, Semgrep OSS 1.182.1, 로컬 규칙 및 SARIF 출력에 한정된다. SARIF 표준이 `codeFlows`를 표현할 수 있다는 사실은 Semgrep OSS가 이 결과에 해당 구조를 출력한다는 뜻이 아니다.

## 실행 조건

- 엔진: Semgrep OSS 1.182.1 (`--oss-only`; SARIF `tool.driver.name`은 `Semgrep OSS`)
- 대상: Phase 3A-1의 합성 A–L fixture를 임시 디렉터리에 복사한 것
- 규칙: 신뢰된 로컬 `rules/experimental/javascript-eval-taint.yml`
- 실행: JSON, 기본 SARIF, SARIF와 `--dataflow-traces`
- 공통 제한: `--metrics=off`, `--disable-version-check`, `--no-autofix`, 60초 timeout, stdout/stderr 합계 2 MB 제한, 임시 HOME/cache
- 네트워크·서비스: Registry, Cloud, Pro Engine, `--trace`, OpenTelemetry, 외부 LLM을 사용하지 않음
- 원본 stdout/SARIF와 임시 합성 입력은 실행 중 메모리/임시 디렉터리에서만 처리하고 저장소에 남기지 않음

`--sarif`와 `--dataflow-traces` 조합은 실제 CLI 실행으로 확인했다. 공식 [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference/)는 `--dataflow-traces`가 text 및 SARIF 출력에 영향을 준다고 설명한다. 실제 OSS 출력은 그 문서상 가능성과 별도로 측정했으며, 이번 SARIF 결과에서는 구조화 흐름 trace를 관찰하지 못했다. `--trace`는 실행하지 않았다.

## 관찰 결과

| 항목 | JSON | 기본 SARIF | SARIF + `--dataflow-traces` |
| --- | ---: | ---: | ---: |
| exit code | 0 | 0 | 0 |
| 출력 크기 | 10,361 B | 8,723 B | 8,723 B |
| 문서 버전 | Semgrep 1.182.1 | SARIF 2.1.0 | SARIF 2.1.0 |
| 실행 수 | 해당 없음 | 1 | 1 |
| 결과 수 | 13 | 13 | 13 |
| SARIF/JSON 규칙·파일·줄·열 서명 일치 | 기준 | 13/13 | 13/13 |
| 모호하거나 중복된 서명 | 해당 없음 | 0 | 0 |
| `codeFlows` | JSON 출력의 `extra.dataflow_trace` 없음 | 13건 모두 필드 없음 | 13건 모두 필드 없음 |
| `threadFlows` / flow locations | 없음 | 0 / 0 | 0 / 0 |

SARIF의 `locations[].physicalLocation`에는 하나의 match 위치가 있었다. 실제 결과가 절대 URI 경로를 담았으므로 테스트는 이를 출력하거나 저장하지 않고, 임시 대상 루트 내부인지 검증한 뒤 상대 fixture 경로로 정규화하여 비교했다. 각 위치에서 양의 start/end line·column을 확인했다. SARIF 위치는 Semgrep match 위치이며, 이를 별도 확인 없이 Source나 Sink argument 위치로 해석하지 않는다.

SARIF 구조는 `version`, 단일 `runs`, `tool.driver`, `results`, `ruleId`, `locations`를 포함했다. result의 키는 `fingerprints`, `locations`, `message`, `properties`, `ruleId`였고 `properties`는 비어 있었다. 각 finding `physicalLocation`은 `artifactLocation`과 `region`을 포함했으며 region에는 시작·종료 line/column과 snippet이 있었다. Source, Sink, 중간 단계는 `codeFlows` 자체가 없으므로 관찰되지 않았다. result의 message, snippet, properties 등 자유 텍스트는 근거 요약에 복사하지 않았다.

## Finding 연결과 기존 계약

테스트에서 JSON과 SARIF result를 순서가 아닌 규칙 ID, 정규화한 fixture 상대 경로, start/end line·column의 multiset 서명으로 비교했다. 13개 모두 유일하게 대응했다. 이 결합은 평가 테스트의 동일 실행 간 구조 확인일 뿐, SARIF 원문을 Finding에 병합하거나 새로운 production 연결 경로를 제공하지 않는다.

`SemgrepAdapter`, `TaintEvidence`, Finding, ScanResult, CLI 및 공개 JSON은 변경하지 않았다. 기존 Finding은 `unverified`이며 `confirmation`은 없다. JSON 기반 TaintEvidence의 `flow_trace_status=absent`, Source/Sink 위치 `unknown` 상태도 그대로 유지한다. SARIF에서 얻은 위치를 JSON 근거에 덧씌우지 않는다.

## 보안 경계와 한계

- 테스트는 로컬 신뢰 규칙 및 합성 fixture만 사용한다. 실제 사용자 프로젝트나 실제 비밀정보를 분석하지 않았다.
- Semgrep은 고정된 로컬 프로세스로 실행하며 metrics/version check를 끄고 autofix를 비활성화했다. 원문 stderr와 SARIF는 사용자 출력에 노출하지 않았다.
- `--trace` 및 외부 전송 기능을 사용하지 않았다. 다만 분석기가 OS 수준 네트워크 차단을 제공하지는 않는다.
- 1:1 match 정합성은 이 합성 집합에서의 관찰이다. 파일 URI/경로 표현이나 Semgrep 버전이 달라지면 다시 검증해야 한다.
- SARIF에 codeFlows가 없으므로 SARIF trace 파서나 TaintEvidence 확장을 추가하지 않았다. text trace를 정규식으로 재구성하지 않는다.

## 검증

Semgrep 전용 CI job이 기존 `tests/test_semgrep_taint_evaluation.py`를 이미 `SEMGREP_REQUIRED=1`로 실행한다. 그 테스트에 SARIF 비교를 추가했으므로 Semgrep 미설치 및 버전 불일치는 성공으로 처리되지 않는다. 단위 테스트는 codeFlows 필드 누락, 빈 배열, 합성 비어 있지 않은 배열, 잘못된 형식을 서로 다른 상태로 구분한다. 합성 형태 검사는 엔진이 해당 구조를 생성했다는 주장이 아니다.

다음 단계에서는 구조화 SARIF trace를 계속 탐색하기보다 결정적 정적 분석 근거를 보강하거나, trace를 제공한다고 명시된 별도 엔진/기능을 별도 승인·평가 범위로 검토하는 편이 낫다. 이번 결과만으로 해당 기능의 지원 여부를 일반화하지 않는다.
