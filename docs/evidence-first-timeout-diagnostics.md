# Phase 2D-2: Evidence-first timeout 원인 진단

## 범위와 환경

기준 커밋은 3a42237b28ffbe24ac1b1465e1a7c6484dec9749이다. 진단은 2026-10-28, Ollama 0.34.2, 로컬 qwen2.5-coder:7b, 동일한 합성 direct_flow Finding 및 1–4행 문맥에서 수행했다. fixture SHA-256은 536dbf…f29c3d다. 최종 canonical A–D 조건은 각 1회 실행했다. request parity가 맞지 않은 예비 C/D 두 호출과 스트리밍 진단 두 호출은 본 비교에서 제외해 별도로 기록한다. 호출 시간 제한은 기존 최대 120초를 넘기지 않았다.

공개 scan CLI와 기본 Provider는 수정하지 않았다. 평가 테스트의 고정 localhost 전송만 계측해 connect/send, HTTP headers 대기, body read, envelope JSON decode, model-content JSON parse, AIReview 검증 시간을 분리했다. redirect를 거부하고 요청 40 KB, 응답 내용 16 KB, Ollama envelope 32 KB와 전체 wall-clock 120초 한도를 유지했다. 스트리밍은 진단 harness에서만 사용했다. 프롬프트·코드·모델 텍스트는 출력하거나 저장하지 않고 고정 fixture hash, 크기, 시간, 허용된 Ollama 완료 통계만 기록했다.

Phase 2C-2의 direct_flow 비교도 검토했다. 두 조건의 fixture와 1–4행 코드는 같았지만 baseline은 run_ollama_review()를, expanded는 context_selection을 추가한 직접 transport를 사용했다. 따라서 request structure와 harness가 달랐고, 당시 결과를 문맥 길이 효과만으로 해석할 수 없었다. 이번 A는 production payload shape를 재현하고 D는 Phase 2D-1의 full Evidence-first payload와 byte-for-byte parity를 단위 검사로 확인했다.

## 타임아웃 위치와 호출 수

Phase 2D-1의 OllamaProvider.timeout=120은 고정 loopback /api/chat의 HTTPConnection socket 제한에 전달됐지만, 해당 평가 로그에는 provider/timeout 코드만 있어 내부 단계는 복구할 수 없다. 기존 Provider는 model inventory 조회(최대 5초), 요청 생성 뒤 POST하며, run_ollama_review()의 안전 진단도 transport timeout을 provider/timeout으로만 분류한다. 기존 _exchange()는 connect/send, response headers, response body 단계를 구분하지 않는다.

이번 계측 경로는 요청 구성, model inventory, connect/send, headers, body read, 외부 Ollama envelope JSON, 내부 model JSON, review schema/reference validation 시간을 나눠 기록한다. Timeout이면 이후 JSON 및 review validation 단계는 실행되지 않는다.

| 조건 | 완료/결과 | 전체 HTTP payload | 서버 관찰 |
| --- | --- | ---: | --- |
| A baseline | 72.52초, JSON/schema 검증 통과, inconclusive, 인용 없음 | 4,691 B | headers 72.4439초 |
| B baseline + 최소 후보 | 62.84초, JSON/schema 검증 통과, inconclusive, 인용 없음 | 5,575 B | headers 62.8329초 |
| C Evidence-first 계약 + 최소 후보 | 45.62초, schema/참조 검증 통과, inconclusive | 4,664 B | headers 45.6199초; 1개 이상 후보 ID 선택 |
| D 전체 Evidence-first | 89.09초, schema/참조 검증 통과, inconclusive | 5,951 B | headers 89.0888초; 1개 이상 후보 ID 선택 |
| D 스트리밍 보조 | 83.19초에 진단 envelope 제한 도달 | D와 동일 내용, stream=true | 첫 NDJSON frame 0.9002초, 첫 non-empty content 0.9005초; 242 frames, 664 B content, 누적 envelope 32,014 B |

Canonical A/B/C/D body fingerprint (SHA-256 앞 12자리): 0965e0153fad, fdd66f7a1610, d30c9dd7f186, 1efa5613b08e. D stream=true fingerprint는 62f01d007e13이다.

Canonical A–D 네 모델 호출은 모두 완료됐다. C와 D는 후보 참조 검증이 통과했으므로 각각 최소 1개 후보를 선택했다. 선택 수와 후보 유형은 이번 harness 출력에 포함하지 않아 미확인이다. 모델의 assessment는 네 조건 모두 inconclusive였으며, 선택된 후보의 보안적 의미가 주장을 뒷받침하는지는 검증되지 않았다.

예비 진단에서 request parity 불일치가 발견되어 C/D를 수정한 harness로 재실행했다. 제외한 C는 97.12초에 완료했지만 candidate_manifest 필드와 source_context_id 순서가 canonical Evidence-first와 달랐다. 제외한 D는 user JSON 키 순서가 달랐고 120초에 timeout_headers였다. 이 두 응답을 A–D 결과나 정확한 Phase 2D-1 재현으로 계산하지 않는다. 예비 요청과 stream 진단을 포함해 Phase 2D-2에서 실제 모델 요청은 총 8회였다: canonical 4회 완료, parity 불일치 C 1회 완료 및 D 1회 timeout, stream 2회는 client envelope 제한으로 종료.

스트리밍 진단은 두 번 했다. 첫 호출은 85.15초에 response size limit으로 종료했으나 계측 코드가 종료 단계 수치를 보존하지 못했다. 두 번째는 83.19초에 32 KB envelope 한도에서 종료해 첫 frame/text 도착 및 누적 크기를 얻었다. 최종 response/done_reason/완료 통계와 최종 AIReview 유효성은 미확인이다. 측정 중 확인한 14-byte read granularity overshoot는 진단 harness가 다음 읽기 크기를 제한해 최대 envelope 한도+1 byte로만 감지하도록 수정했다. 기본 Provider 동작은 변경하지 않았다.

120초는 connect/send 전체의 총 시간이 아니라 socket idle timeout으로 Provider에 적용된다. 진단 harness는 별도의 절대 wall-clock deadline도 적용했다. Canonical A–D에서 각 요청 전송·body 수신·JSON·review 검증 단계는 짧았고, 가장 긴 대기는 비스트리밍 response headers 대기였다. 예비 비-parity D timeout은 headers 단계였지만 그 결과는 canonical 비교에서 제외했다. 이전 Phase 2D-1 요청의 세부 하위 단계는 확인할 수 없다.

## 요청 구성 비교

각 조건은 같은 모델, Finding, 4개 코드 줄, stream=false, temperature=0, think=false를 사용한다. 아래 payload 크기는 schema와 두 messages를 포함한 실제 JSON body 크기다. 해시는 고정된 직렬화 순서의 JSON body fingerprint이며 코드 원문은 보고되지 않는다.

| 조건 | system B | user B | payload B | 후보 수 / 후보 metadata B | schema B / 필수 출력 필드 |
| --- | ---: | ---: | ---: | ---: | --- |
| A baseline | 1,013 | 1,151 | 4,691 | 0 / 2 | 2,250 / 7 |
| B baseline + 최소 후보 | 1,013 | 1,973 | 5,575 | 5 / 767 | 2,250 / 7 |
| C Evidence-first + 최소 후보 | 782 | 2,062 | 4,664 | 5 / 767 | 1,477 / 8 |
| D Evidence-first 전체 후보 | 782 | 3,249 | 5,951 | 5 / 1,904 | 1,477 / 8 |

A와 B는 동일한 system 지침·출력 schema·생성 옵션을 사용하고 user 데이터에 최소 후보 목록만 추가한다. B→C는 후보 정보는 compact 형태로 유지하지만 trusted instructions와 응답 계약을 함께 바꿨으므로 단일 변수 비교가 아니다. C와 D는 schema, 지침, context, 모델 옵션, user 필드 이름과 순서를 고정하고 후보 객체의 metadata 수준만 바꿨다. 따라서 C→D는 compact 후보 객체와 전체 provenance 객체의 차이를 비교한다. 작은 합성 입력 한 건이므로 metadata 확대가 지연을 일으킨 인과 효과를 입증하지는 않는다.

baseline 응답 schema는 7개 필수 필드를 가지며 2,250 B다. Evidence-first schema는 필수 필드 8개지만 1,477 B로 더 작다. 따라서 schema JSON 바이트 크기 자체가 추가 지연의 원인이라고 볼 근거는 없다. canonical C와 D는 모두 완료되어 schema/참조 검증을 통과했지만 assessment는 inconclusive였다. D가 C보다 느리고 prompt/output token 수가 컸으나 한 번씩의 관측만으로 후보 metadata가 그 차이를 야기했다고 단정할 수 없다.

요청에는 num_predict 또는 모델 출력 token cap이 지정되지 않았다. MAX_RESPONSE_BYTES는 non-stream 전체 응답이 도착한 뒤 적용되므로 generation 자체를 제한하지 않는다. 진단 경로의 절대 120초 deadline과 16 KB 콘텐츠 및 32 KB envelope 제한은 유지했고, 장시간 출력을 성공으로 취급하지 않았다.

## Ollama 생성 통계와 시스템 관찰

Ollama가 완료한 canonical A–D 호출에서 반환한 metadata:

| 조건 | total / load (초) | prompt tokens / prompt eval (초) | eval tokens / eval (초) | done_reason |
| --- | --- | --- | --- | --- |
| A | 72.323 / 9.000 | 526 / 21.096 | 138 / 42.191 | stop |
| B | 62.831 / 0.170 | 971 / 20.760 | 127 / 41.509 | stop |
| C canonical | 45.618 / 0.003 | 988 / 5.731 | 355 / 39.837 | stop |
| D canonical | 89.087 / 0.003 | 1,524 / 11.672 | 653 / 77.328 | stop |

반환된 total_duration은 테스트 harness의 HTTP 왕복 시간과 약간 다를 수 있다. 예비 비-parity D timeout과 스트리밍 진단은 완료 통계가 없지만 canonical D는 완료됐다.

Ollama CLI는 /opt/homebrew/opt/ollama/bin/ollama에 있었고 shell PATH에는 없었다. ollama --version은 0.34.2다. 모델 inventory에는 해당 로컬 모델 하나가 있었고 /api/ps에는 다른 모델이 없었다. 모델은 약 4.64 GB VRAM으로 100% GPU에 적재됐다. 프로세스 샘플에서 llama-server RSS는 약 4.74 GB였고 진단 종료 후 CPU는 0–0.2%였다. 이는 timeout 이후 서버 추론이 계속됐다는 증거가 아니다. 이번 실험은 동시 Ollama 모델 호출을 하지 않았다.

macOS의 논리 CPU 수는 8, 물리 메모리는 16 GiB다. 첫 확인에서 시스템 메모리 여유 지표는 78%였고, 실행 후 관찰에서는 약 31–42% 사이였다. 메모리 사용 변화 전체를 Ollama에 귀속할 수 없고, GPU 메모리 경쟁 및 다른 프로세스의 순간 자원 사용은 직접 측정하지 않았다. 따라서 로컬 시스템 자원은 잠재 교란 요인이지만 D 지연의 단독 원인으로 확인되지 않았다.

## 스트리밍 결과 및 원인 판단

D와 같은 합성 입력으로 별도 stream=true 진단을 두 번 수행했다. 계측이 완전했던 호출은 첫 frame과 첫 non-empty model content가 약 0.9초에 도착했다. 이후 83.19초까지 242 NDJSON frame, 664 bytes의 content를 받았고 전체 frame envelope가 32 KB 상한에 도달해 클라이언트가 종료했다. 이는 모델이 응답을 시작하기까지 120초가 걸린 것이 아님을 보여준다. 다만 스트리밍 동작은 비스트리밍과 다를 수 있고, 최종 응답이 없었으므로 전체 생성 완료시간은 측정되지 않았다.

### 확인된 사실

- 모델 inventory와 요청 구성은 짧게 완료되고 요청 전송은 1 ms 미만이었다.
- Canonical A–D non-stream 요청은 모두 120초 이내에 headers 및 완료 응답을 받았다.
- Canonical D의 prompt evaluation은 11.67초, generation은 77.33초였다. 요청 준비나 HTTP body 수신이 지연을 만든 것이 아니다.
- 같은 D 입력을 stream=true로 보냈을 때 첫 content는 0.9005초에 도착했으나, 완료 전에 안전한 envelope byte 상한을 소진했다.
- 후보 없는 baseline과 후보 metadata를 넣은 네 조건 모두 inconclusive였다. C와 D에서 구조적으로 유효한 후보 참조는 관찰됐지만 의미적 정확도 개선은 검증되지 않았다.

### 원인이 확정되지 않은 점

- Phase 2D-1의 4회 D timeout과 이번 canonical D 완료 차이는 모델 실행의 변동성을 보이지만, 정확한 이전 응답의 서버 통계는 없다.
- 스트리밍 응답 제한은 NDJSON frame metadata를 포함한 전체 envelope 제한이므로 content가 664 B였다는 사실은 최종 출력 길이를 뜻하지 않는다.
- C/D 모두 후보 field name과 user JSON 순서는 동일하게 맞췄다. 그래도 한 번씩의 실행으로 생성 지연 차이의 원인을 확정할 수 없다.
- 작은 표본 한 번씩으로 모델 변동성, 서버 내부 queue, GPU/메모리 경쟁을 배제할 수 없다.

Phase 2D-1의 timeout이 연결·요청 구성·최초 토큰 대기에서 발생했다고 볼 증거는 없다. 이번 stream 요청에서 첫 content는 0.9초에 도착했고, canonical non-stream D는 89.09초에 완료됐다. A–D의 지연 대부분은 Ollama prompt evaluation 및 token generation이었다. 이전 D timeout과 재현 실행의 차이는 completion 길이·생성 속도 또는 실행 간 자원 상태 변동과 양립하지만, 타임아웃 당시 completion 통계가 없어 하나의 원인으로 확정할 수 없다.

## 보안 및 계약 회귀

진단은 해시가 고정된 합성 fixture만 사용했다. HTTP target은 127.0.0.1:11434로 고정되고 프록시 환경변수는 사용하지 않는다. redirect 거부, 응답 크기·wall-clock 상한, 비밀정보 검사, no-tools 요청, prompt injection 신뢰 경계, Finding unverified/confirmation 불변성을 유지했다. 스트리밍은 test-only 진단으로 공개 CLI 및 Provider에 연결되지 않는다. Ollama 서비스 자체의 OS 네트워크 격리는 보장하지 않는다.

## 권고

우선 요청 직렬화의 compact/전체 후보 표현과 응답 생성 길이를 통제된 실험으로 분리한다. 필요 시 테스트 전용 output token cap을 별도 변수로 시험하되 schema·근거 검증 조건을 낮추지 않고, 동일 조건 baseline도 함께 측정한다. 모델 응답 완료 통계를 수집할 수 없는 경우는 incomplete/timeout으로 남기고, 추정 token 수나 성공으로 간주하지 않는다.
