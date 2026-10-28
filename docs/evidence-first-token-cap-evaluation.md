# Phase 2D-3: Ollama 출력 토큰 상한 평가

## 범위와 결정

평가는 고정 합성 `direct_flow` fixture만 대상으로 수행했다. 실제 저장소 코드나 자격증명은 사용하지 않았다. `OllamaProvider`, 기본 `run_ollama_review()`, 공개 CLI 및 Finding/AIReview 계약은 수정하지 않았다. 테스트 전용 harness가 기존 canonical A baseline 및 D Evidence-first payload에 `options.num_predict` 하나만 추가해 고정 loopback Ollama에 보냈다. 요청은 `stream=false`, `think=false`, `temperature=0`이고 모델·Finding·4줄 문맥·출력 schema·후보 bundle은 고정했다.

Ollama API 문서는 `options.num_predict`를 생성 최대 토큰 수로 정의한다 ([API 문서](https://github.com/ollama/ollama/blob/main/docs/api.md), [API schema](https://github.com/ollama/ollama/blob/main/docs/openapi.yaml)). 실제 로컬 Ollama 0.34.2에서도 D 요청의 `eval_count`가 설정값과 정확히 일치하고 `done_reason=length`가 반환되어 옵션이 적용됨을 확인했다. 이는 이 모델/서버 조합의 실측이며 다른 버전 동작을 보장하지 않는다.

실험 중단 기준은 상한 도달이 연속 발생하면 추가 호출하지 않는 것이다. 먼저 A/D를 256에서 실행했고 D가 상한에 도달해 512에서 다시 A/D를 실행했다. 두 번째 D도 상한에 도달해 768 및 B/C 실험은 중단했다. 각 요청은 기존 120초 이내로 제한했으며 반복 실행을 추가하지 않았다.

## 환경 및 요청 차이

- Ollama 0.34.2, `qwen2.5-coder:7b`, digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- 8 CPU, 16 GiB RAM. `/api/ps`에서 요청 후 모델 적재 크기 4,638,040,390 B 및 VRAM 사용 크기 동일 값을 확인했다. A/256에서는 요청 전 미적재, 이후 요청 전부터 적재되어 있었다.
- 시스템 메모리 표본은 실행 시점별 편차가 있고 Ollama 프로세스 RSS 및 GPU 경합을 별도로 귀속할 수 없었다. 동시 모델 요청은 하지 않았다. 따라서 자원 압박이 지연의 원인인지 확인하지 못했다.
- 변경 변수는 `options.num_predict`뿐이다. 요청 크기 차이는 숫자 직렬화에 따른 18 B이며, 나머지 schema·system·user payload 바이트는 동일했다.
- A: payload 4,709 B, schema 2,250 B, system 1,013 B, user 1,151 B, 코드 4줄, 후보 없음.
- D: payload 5,969 B, schema 1,477 B, system 782 B, user 3,249 B, 코드 4줄, 후보 5개(각 1개: argument, call, finding location, return, variable declaration).
- 출력 schema, trusted instructions, 후보 정보는 A와 D 본래 계약 차이로 다르다. 따라서 A↔D는 상한 효과의 직접 비교가 아니다. 동일 조건의 상한별 비교는 A-256↔A-512 및 D-256↔D-512이다.

요청 지문은 코드 내용 대신 canonical JSON body의 SHA-256으로 기록했다. 제한 256: A `93c459d2…45d0b1c`, D `bd80f84a…e9db7a64`; 제한 512: A `b2c2fa52…1c18d0c0b`, D `6c81533d…d773dd6`. 요청·응답 텍스트는 로그나 파일에 저장하지 않았다.

## 실제 호출 결과

| 조건 | 제한 | client 총시간 | prompt tokens / 평가 시간 | 출력 tokens / 생성 시간 | tokens/s | 종료 | JSON/schema | AIReview |
|---|---:|---:|---:|---:|---:|---|---|---|
| A baseline | 256 | 30.83 s | 526 / 6.06 s | 138 / 16.41 s | 8.41 | `stop` | 통과 | 수용, inconclusive |
| D Evidence-first | 256 | 54.08 s | 1,524 / 21.38 s | 256 / 32.15 s | 7.96 | `length` | JSON 파싱 실패 | 거부 |
| A baseline | 512 | 12.77 s | 526 / 0.14 s | 122 / 12.56 s | 9.71 | `stop` | 통과 | 수용, inconclusive |
| D Evidence-first | 512 | 78.88 s | 1,524 / 0.17 s | 512 / 78.66 s | 6.51 | `length` | JSON 파싱 실패 | 거부 |

모든 호출에서 Ollama의 `total_duration`, `load_duration`, `prompt_eval_count`, `prompt_eval_duration`, `eval_count`, `eval_duration`, `done_reason`을 가능한 범위에서 읽었다. 완료 통계는 응답 envelope에서 직접 확인했다. 256 D는 load 0.302 s, 512 D는 0.0045 s였고, 두 응답의 `prompt_eval_duration`은 크게 달랐다. 요청 간 결과 차이를 상한만의 효과로 단정할 수 없다.

256에서 A의 138 출력 토큰과 512에서 A의 122 토큰은 모두 설정값보다 작고 정상 종료했다. A에서 상한 때문에 속도가 빨라졌다는 증거는 없다. 각 실행의 prompt evaluation 및 모델 적재 상태가 달랐고, 이는 변동성의 관찰 근거다.

D는 상한 256 및 512에서 각각 해당 상한만큼 생성한 뒤 `done_reason=length`로 종료했다. 모델 content는 각각 741 B, 1,263 B였지만 JSON이 불완전해 파싱에 실패했고 Evidence-first 검증 및 후보 ID 참조 검증까지 도달하지 못했다. 따라서 선택된 후보 수·종류는 **0으로 확인된 것이 아니라 검증 불가**다. 어느 응답도 AIReview로 수용하지 않았고 응답을 복구하거나 필드를 채우지 않았다.

이 fixture의 사전 기대는 `likely_true_positive`였다. 합성 함수 안에서 `request.query.expression`을 변수에 대입하고 같은 값을 `eval()`에 전달하기 때문이다. 이 소규모 코드에서 직접적인 source-to-sink 관계가 보이지만, 실제 웹 요청 도달성은 프레임워크 실행 문맥에 의존한다. A가 두 번 `inconclusive`를 반환한 것은 이 fixture 기대와 일치하지 않는다. D는 상한 절단으로 판단 자체를 검증할 수 없었다.

무제한 Phase 2D-2의 D 참고값은 653 출력 토큰, 생성 77.33 s, 전체 89.09 s였다. 새 512 D는 출력 생성 78.66 s로 참고 실행보다 빨라지지 않았고, JSON도 완성되지 않았다. 256 D는 54.08 s로 짧았지만 생성 제한에서 잘려 검증 가능한 결과가 아니었다. 서로 다른 시점의 실행이고 warm/cold 적재, prompt 평가 시간, 로컬 자원 변동이 있어 인과적 성능 비교로 해석하지 않는다.

## 검증 및 보안 경계

실험 harness는 고정 `127.0.0.1:11434`와 `/api/chat`만 사용하며 프록시, redirect, 외부 API, 도구 호출을 사용하지 않는다. 기존 요청 40 KB, content 16 KB, envelope 32 KB, 요청별 120초 제한을 유지한다. redacted/truncated/unavailable 문맥의 기본 경로 차단도 변경하지 않았다. Finding은 계속 `unverified`이고 confirmation은 생성하지 않는다. 이번 live fixture에는 민감정보나 prompt injection 문구가 포함되지 않았으며 기존 합성 회귀 테스트에서 해당 경계를 재검증했다. Ollama 프로세스 자체에 OS 네트워크 차단이 있다는 보장은 없다.

`done=true`만으로 성공 처리하지 않는다. `done_reason=length` 또는 `eval_count >= num_predict`는 `token_limit_reached`로 분류한다. 이후 JSON 파싱이나 schema 검증이 우연히 통과하더라도 해당 결과는 수용하지 않는다. 현재 두 D는 추가로 JSON 자체가 잘렸다. Provider·연결 타임아웃, response size limit 및 schema/reference 검증 경계는 기존 정책 그대로 유지한다.

## 평가 결론과 한계

- 서버가 `num_predict`를 실제 적용했으며, 두 D 실행에서 정확히 제한 토큰 수 생성 및 `length` 종료가 관찰됐다.
- A는 낮은 상한에서도 응답이 짧아 정상 수용됐지만 모두 inconclusive이고, A의 상한이 속도를 개선했다는 결론은 낼 수 없다.
- D는 256과 512 모두 JSON 절단으로 검증에 실패했고, 유효한 EvidenceCandidate 선택은 관찰되지 않았다.
- 지연은 생성이 주된 비용인 실행이 있었으나, 반복 수가 매우 작고 모델 적재·prompt 평가 변동이 있어 토큰 상한의 성능 효과를 일반화할 수 없다.
- 연속된 D 상한 종료가 중단 기준에 해당해 768, B/C, 반복 안정성 평가는 미실행이다. 따라서 더 큰 상한이 완전 응답을 만들지 여부는 미확인이다.
- 동일한 상한에서의 반복 호출은 하지 않아 결과 안정성/재현성은 미측정이다.
- 기본 Provider에 token cap을 적용하거나 Evidence-first 효과를 주장할 근거는 확보되지 않았다. 현재 설정 그대로 기본 경로를 유지한다.
