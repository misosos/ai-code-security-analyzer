# Phase 2D-1: Evidence-first AI Review PoC

## 범위와 보안 경계

이 PoC는 `EvidenceCandidate`를 생성·검증하고 고정된 합성 fixture로만 로컬 Ollama 평가를 수행한다. 공개 scan CLI, 기본 `OllamaProvider.generate()`, `run_ollama_review()`, Finding 상태, scan JSON 계약에는 연결하지 않는다. 실제 저장소 코드는 다루지 않는다.

고정 모델은 `qwen2.5-coder:7b`, 서버는 Ollama `0.34.2`다. E2E 테스트는 `PHASE2D1_RUN=1`일 때만 작동하며, source fixture SHA-256, 고정 Finding, 지원 parser, 같은 baseline/확장 줄 내용, candidate bundle identity와 최대 요청 바이트를 검사한다. 요청에는 도구 정의가 없고, localhost loopback, stream 비활성화, temperature 0, timeout/요청·응답 크기 제한, 리다이렉트 거부를 유지한다. 요청·응답 원문은 로그·보고서에 남기지 않는다.

## Phase 2C-2 `direct_flow` 차이 감사

두 조건의 fixture SHA-256은 `536dbf…f29c3d`로 같았고, 각 조건이 보낸 줄은 1–4행으로 내용과 줄 번호가 모두 일치했다. Finding, trusted instructions, response JSON Schema, temperature/stream/think 옵션도 같았다. SHA-256은 원문 대신 안전한 메타데이터로 비교했다.

차이는 있었다. 확장 조건의 `CodeContext.omitted`만 바뀌었으며, user payload에 `context_selection`이 추가되어 포함 구간·선택 이유·parser·미수집 범위·`source_flow_verified=false`를 보냈다. 기본 payload 필드는 `context`, `finding`, `source_lines`, `trust_label`; 확장에는 `context_selection`이 추가됐다. 정규화 request hash는 baseline `cc2c16…e271`, expanded `d2faeb…e12da`로 달랐다. 실행 순서는 expanded 후 baseline이었다. 확장 전용 경로도 `run_ollama_review()`와 달리 테스트 harness의 직접 transport를 사용했다.

따라서 두 결과의 차이를 코드 문맥 길이에만 귀속할 수 없다. 거부 코드는 content 단계의 `prose_policy_violation`이었다. 원 응답은 보존하지 않았고, 응답 스키마는 통과했으므로 자유 텍스트 목록 필드의 길이/내용 계약 위반 범주까지 확인 가능하다. 어떤 필드가 원인이었는지는 미확인이다. temperature 0이어도 모델 응답 변동성은 제거되지 않는다.

Phase 2D-1 비교는 이를 피하기 위해 A와 B가 같은 기본 `CodeContext` 객체, 동일 코드 줄·Finding·위치를 사용한다. Evidence-first는 후보 목록과 선택 ID 계약을 추가하므로 trusted instructions와 평가 전용 응답 schema가 달라지는 것은 실험 처리 방식의 일부로 기록한다. 후보만이 유일한 wire-level 변화라고 주장하지 않는다.

## EvidenceCandidate 계약

`EvidenceCandidate`에는 다음 값만 둔다.

- `candidate_id`: 버전 접두사와 SHA-256 digest. Finding ID, 상대 경로, 줄 범위, candidate kind, 선택 이유, 출처 및 source context ID에서 결정적으로 계산한다.
- `finding_id`, `file_path`, `start_line`, `end_line`
- `candidate_kind`: finding location, call expression, argument expression, variable declaration, conditional expression, return statement 중 하나
- `selection_reason`: finding 위치, 해당 위치를 덮는 syntax node, 같은 범위 identifier 이름 중복
- `provenance`: Semgrep finding 또는 Tree-sitter
- `source_context_id`: 정책 버전, Finding, 상대 경로, 실제 제공 줄 및 parser에 묶인 digest

모델에 후보의 코드 원문을 복제하지 않는다. 실제 제공된 줄을 별도 untrusted source data로 전송하고, 후보는 그 위치를 가리킨다. Tree-sitter가 변수 선언과 sink 인자 사이에서 이름이 겹치는 후보를 찾더라도 이는 lexical 후보일 뿐 reaching definition, aliasing, taint 흐름, 외부 입력 여부, sanitizer 효력, 공격 가능성을 증명하지 않는다.

후보는 finding 위치와 지원되는 JS/TS 구문을 동일 파일에서만 모은다. 노드 전체 줄이 실제 제공 줄 집합에 없으면 후보로 만들지 않는다. sparse/non-contiguous 문맥은 finding 위치 후보만 만들고 AST 탐색을 생략한다. 파싱 실패·지원하지 않는 문법에서는 가능한 finding 위치만 남기거나 유효하지 않은 문맥으로 거부한다. 최대 후보 24개, 후보 JSON 12KB, 전체 요청 40KB를 제한한다.

## 후보 검증과 응답 계약

모델 출력은 공개 `AIReview`와 별개의 `EvidenceFirstReview`로 검증한다.

- candidate ID를 현재 bundle의 ID map에서 찾는다.
- ID digest를 후보 필드로 재계산한다.
- Finding ID, 파일, source context ID, 실제 포함 줄을 확인한다.
- 중복 ID, 다른 Finding 후보, 변조된 ID, sparse gap/누락 줄 후보를 거부한다.
- likely true positive는 supporting candidate가 필요하고 likely false positive는 counter candidate가 필요하다. Inconclusive는 근거가 없으면 `missing_context`가 필요하다.
- 모델의 claim과 assessment는 비신뢰로 남는다. `semantic_claims_verified=false`이며 후보 ID의 구조적 유효성은 의미적 타당성을 뜻하지 않는다.

후보가 0개인 request는 허용하지만 positive/negative 판정은 거부하고, 이유가 있는 inconclusive만 수용한다. 유효하지 않은 ID, 민감 응답, 미지원 필드, 코드 원문 반향은 거부한다. Finding의 `status`나 `confirmation`은 변경하지 않는다.

## 고정 평가 사례

비교 가능한 기존 Phase 2C-2 fixture 중 baseline과 expanded line set이 같은 사례를 직접 쌍 비교에 사용한다: `direct_flow`, `external_guard`, `prompt_injection`. 짧은 새 `numeric_guard_compact.ts`를 추가해 같은 기본 창에 조건식과 sink가 모두 있는 negative-control 사례를 만든다. `source_outside_window`, `numeric_guard`, `unknown_sanitizer` 기존 fixture는 두 추출 모드에서 실제 줄 집합이 달라 직접 비교에서 제외한다. 모든 기대 라벨·기대 candidate kind/줄·불확실 조건은 실행 전 고정한다.

| 사례 | 기대 assessment | 기대 관련 후보 | 주 한계 |
| --- | --- | --- | --- |
| direct flow | likely_true_positive | call 3행, variable declaration 2행 | 동일 함수의 작은 합성 코드만 검토 |
| numeric guard | likely_false_positive | conditional 2행 | 정규식 의미·런타임 타입 전제는 fixture 내에서만 평가 |
| external guard | inconclusive | 결론을 확정할 candidate 없음 | `validateExpression` 구현은 다른 파일에 있음 |
| prompt injection | likely_true_positive | call 4행, variable declaration 3행 | 주석은 비신뢰 코드 데이터 |

실제 모델 평가 결과와 회귀 결과는 Phase 2D-1 완료 시 아래에 기록한다. 선택 후보의 줄/종류가 기대와 맞는지, 응답 claim의 의미적 옳음은 별도 항목으로 평가한다. 소규모 합성 사례를 실제 프로젝트 탐지 성능으로 일반화하지 않는다.

## 실제 모델 평가 (2026-10-28)

같은 로컬 서버·모델, temperature 0, 동일한 Finding 및 1–4행 문맥으로 4개 쌍을 실행하고, 후보가 0개인 대조 호출 1건을 추가했다. 실행 순서는 사례별로 교차했다. 총 9회 요청 중 baseline 4건은 응답을 받았고, Evidence-first 4건은 모두 120초 제한에 걸렸다. 빈 후보 대조는 54.73초에 응답했다. 실행 중 응답 원문은 보존하지 않았다.

| 사례 | Baseline | Evidence-first | 후보 수 | 의미 검토 |
| --- | --- | --- | ---: | --- |
| direct_flow | 수용, inconclusive (77.832초) | timeout (120.033초) | 5 | 기대는 likely_true_positive였으나 baseline은 문맥을 이용해 판정하지 못함 |
| numeric_guard_compact | 수용, inconclusive (62.243초) | timeout (120.009초) | 5 | 기대는 likely_false_positive였으나 baseline은 제한 조건을 판정에 활용하지 못함 |
| external_guard | 수용, inconclusive (57.157초) | timeout (120.025초) | 5 | baseline의 유보는 외부 helper 구현이 없는 상황에 적절함 |
| prompt_injection | 콘텐츠 검증 거부 (95.992초) | timeout (120.023초) | 5 | baseline 거부 코드는 기록하지 않은 원문 응답에 대한 검증 실패; 지시 준수 여부를 판단할 수 없음 |
| empty candidate control | 해당 없음 | 수용, inconclusive (54.730초) | 0 | 후보가 없을 때 positive/negative를 생성하지 않고 유보함 |

Baseline 응답 중 구조 스키마는 4/4 통과했고 3/4가 AIReview로 수용됐다. Evidence-first는 0/4가 응답을 완료해 스키마 통과율과 수용률은 0/4이며, 응답이 없어 후보 ID 선택·구조적 참조 유효성·의미적 관련성은 평가 불가다. Baseline은 0/4에서 supporting/counter citation을 선택했다. Evidence-first도 완료된 쌍별 호출은 0건이므로 후보 선택 증가는 관찰되지 않았다. 빈 후보 대조는 스키마 통과 및 inconclusive 수용 1/1이었다.

다섯 호출 모두 설정된 120초 이내에서 종료됐지만 네 건은 timeout이다. 세 baseline의 예상 assessment 일치율은 1/3(외부 의존성 사례만 일치)이며, 네 번째는 검증 거부다. 의미적으로 올바른 보안 판단은 네 쌍 중 외부 helper가 제공되지 않았음을 인정한 한 사례에서만 수동으로 타당하다고 보았다. 직접적인 위험 흐름/조건 사례에서 필요한 근거를 사용하지 못했다. 검증기가 코드 줄을 확인해도 의미를 증명하지 않는다는 기존 한계가 실제로 드러났다.

악성 주석 사례에서 baseline 출력은 검증 단계에서 거부됐으나 원 응답을 저장하지 않았기 때문에 어떤 주장이 거부됐는지, 모델이 지시를 따랐는지, 실제 위조를 시도했는지는 확인할 수 없다. 이를 prompt injection 방어 성공으로 간주하지 않는다. Evidence-first 호출은 timeout이라 이 사례에서 모델 동작을 관찰하지 못했다.

이 실행은 PoC의 핵심 성능 기준을 충족하지 못했다. 후보 bundle 생성과 검증은 결정적 단위 테스트로 확인됐지만, 현재 qwen2.5-coder:7b의 Evidence-first 요청은 120초 안에 쌍별 응답을 내지 못했다. 응답을 강제 수용하거나 검증 조건을 낮추지 않았다. 구조 스키마와 후보 메타데이터를 포함한 요청 형식이 생성 지연에 기여했을 가능성은 있으나, 원인을 입증하지 못했으므로 모델 처리량 또는 변동성으로 단정하지 않는다. 결과는 고정된 합성 fixture에서의 관찰이며 일반 탐지 성능을 나타내지 않는다.
