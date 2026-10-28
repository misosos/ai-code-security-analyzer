# Phase 2D-4: Minimal Evidence-first 출력 계약 평가

## 범위와 사전 기준

기존 Evidence-first 응답 계약과 평가 전용 최소 계약을 고정 합성 `direct_flow.ts` fixture에서 비교했다. fixture SHA-256은 `536dbf5376d1e6f5a8f759674baae2063ab43cb40589b012d132ead4e2f29c3d`다. 사전 기대 평가는 `likely_true_positive`; 의미상 기대 후보는 같은 함수 안의 호출·인자·값 선언 위치이며, 구조적으로 유효한 ID 선택만으로 데이터 흐름이나 취약점을 증명하지 않는다는 기준을 유지했다.

기존 조건은 Phase 2D-1의 8개 필수 출력 필드(assessment, 요약, finding ID, supporting/counter evidence, 부족 문맥 상태와 설명, 제한)를 사용한다. 새 조건은 별도 평가 전용 모델의 세 필드만 사용한다: `assessment`, `selected_candidate_ids`, `missing_context_reason`. 세 필드는 모두 schema에서 required이고, reason은 nullable이다. 추가 속성은 거부한다. 양쪽 조건 모두 동일한 다섯 EvidenceCandidate와 동일한 코드 문맥을 입력으로 받는다. 새 결과는 공개 `AIReview`로 변환하지 않는다.

방향성 assessment에는 선택 후보가 하나 이상 필요하고, inconclusive에는 구체적인 비어 있지 않은 부족 문맥 이유가 필요하다. 방향성 판단의 구조적 최소 기준으로 positive는 호출·인자·변수 선언·return 후보 중 하나를, negative는 조건식 후보를 요구한다. `finding_location` 하나만 선택한 방향성 주장은 거부한다. 이 kind 기준은 의미 관련성의 완전한 검증이 아니라, 일반 위치 표식만으로 확정적인 평가를 통과시키지 않는 보수적 검사다. 후보 묶음은 Finding, 파일, 포함된 줄, source context hash, candidate ID 재계산으로 검증한다. 결과는 `semantic_claims_verified=false`로 고정한다.

## 요청 계약의 크기

두 요청 모두 모델 `qwen2.5-coder:7b`, temperature 0, `num_predict`별 비교, 4개 동일 코드 줄, 동일 Finding과 후보 다섯 개를 사용했다. 달라진 항목은 출력 schema와 이에 필요한 최소 지침 및 후보 표현이다.

| 측정 항목 | 기존 Evidence-first | 최소 계약 |
| --- | ---: | ---: |
| 요청 JSON 크기 | 5,951 B | 3,774 B |
| 응답 JSON Schema | 1,477 B | 651 B |
| 필수 출력 필드 | 8 | 3 |
| trusted system 지침 | 782 B | 701 B |
| user 메시지 | 3,249 B | 2,062 B |
| 후보 수 | 5 | 5 |
| 후보 메타데이터 | 1,904 B | 767 B |

최소 조건은 요청 크기를 2,177 B(36.6%), schema를 826 B(55.9%), 후보 표현을 1,137 B 줄였다. 이는 출력 계약·직렬화 전반을 함께 바꾼 비교이므로 schema만의 인과 효과로 볼 수 없다.

## 실제 로컬 모델 평가

실행 환경은 Ollama 0.34.2, 모델 `qwen2.5-coder:7b`, digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`, localhost `127.0.0.1:11434`였다. 실행 순서는 256에서 기존→최소, 512에서 최소→기존으로 교차했다. 각 HTTP 요청 timeout은 120초, 응답 상한은 기존 16 KB를 유지했다. 모델 응답 원문은 출력·저장하지 않았다.

| 상한 | 계약 | 결과 | 생성 토큰 | content | Schema / 후보 검증 | 평가 |
| ---: | --- | --- | ---: | ---: | --- | --- |
| 256 | 기존 | 120.016초 timeout | 미측정 | 미수신 | 미실행 | AIReview 수용 없음 |
| 256 | 최소 | 69.171초, `done_reason=stop` | 123 | 340 B, 유효 JSON | 통과 / 통과 | `inconclusive`, 후보 1개 선택 |
| 512 | 최소 | 35.198초, `done_reason=stop` | 123 | 340 B, 유효 JSON | 통과 / 통과 | `inconclusive`, 후보 1개 선택 |
| 512 | 기존 | 120.004초 timeout | 미측정 | 미수신 | 미실행 | AIReview 수용 없음 |

최소 응답 두 건 모두 256 상한 미만의 123 token으로 정상 종료했다. 256/512에서 같은 출력 길이가 나온 것은 이 fixture의 최소 계약 응답이 설정 상한에 닿지 않았음을 뜻한다. 512 요청이 더 빨랐다고 단정할 수 없다. prompt evaluation은 첫 호출에서 978 token/33.685초, 두 번째 warm 호출에서 978 token/0.205초로 차이가 커 모델 적재·캐시·실행 시점 효과가 섞여 있다.

서버 응답에서 읽은 `total_duration`, `load_duration`, `prompt_eval_duration`, `eval_duration` 값은 그대로 계측했다. 두 최소 호출에서 Ollama가 돌려준 `eval_duration` 값은 각각 `6288247371000`, `1005372564000`이고, 대응하는 `total_duration`은 `69072625625`, `35182938167`이었다. 이 값들은 동일 단위라고 가정할 때 total보다 커 서로 일관되지 않는다. 원인을 확인할 수 없어 생성 속도(tokens/sec) 계산이나 해당 eval duration의 시간 해석은 하지 않았다. 클라이언트 전체 시간, 응답의 `eval_count`, 종료 이유는 별도로 확인된 값이다.

## 근거 선택과 의미 평가

기존 계약은 두 상한에서 모두 timeout이라 출력 완성률 0/2이고, 근거 선택은 측정할 수 없었다. 최소 계약은 JSON/schema/후보 참조 검증을 2/2 통과했지만, 두 응답 모두 `finding_location` 후보 하나만 선택했다. 사전 기대한 호출·인자·변수 선언 anchor와의 겹침은 0건이었다. 두 assessment 모두 expected positive와 불일치하는 `inconclusive`였다.

최소 계약의 inconclusive 응답은 validator가 요구하는 비어 있지 않은 `missing_context_reason` 검증을 통과했다. 이유의 의미를 원문 없이 별도 기록하지 않았으므로 그 내용의 타당성은 재평가하지 않았다. 구조적 ID 유효성은 통과했지만 선택 후보는 사전 정의된 의미 관련 후보와 맞지 않았다. 따라서 근거 선택이나 보안 판단의 질이 개선됐다는 증거는 없다. 다만 기존 조건은 timeout이므로 이번 표본은 출력 계약의 성공률을 비교했을 뿐 동등한 두 완료 응답의 의미적 정확도를 쌍별 비교하지 못했다.

## 보안·계약 경계

- 실제 전송은 정확한 `AI_CODE_SECURITY_RUN_OLLAMA=1` opt-in에서만 수행했다.
- 합성 fixture hash가 실행 전후 확인됐다. 실제 저장소 코드, 비밀정보, 외부 Provider는 사용하지 않았다.
- 전송 위치는 고정 loopback이며 redirect/proxy 경로를 추가하지 않았다. 도구 호출은 금지되고, 기존 `done`, 크기 및 timeout 검사를 유지했다.
- 기존 Evidence-first validator와 새 minimal validator 모두 후보 ID, Finding/context/file/포함 줄 일치를 검사한다. 민감 출력은 거부한다.
- Finding은 `unverified`로 유지됐고 confirmation은 생성되지 않았다. 공개 AIReview, CLI, Finding, ScanResult 계약과 기본 Ollama Provider는 변경하지 않았다.
- 기본 pytest에서 실제 모델 호출은 수행하지 않았다. Ollama 서버 프로세스에 대한 OS 수준 외부 네트워크 격리는 분석기가 보장하지 않는다.

## 결론과 제한

이 고정 fixture에서 최소 출력 계약은 두 번 모두 256/512 상한 안에서 짧은 정상 JSON을 만들었고, 기존 계약은 두 번 모두 120초 timeout이었다. 그러나 선택한 후보는 두 번 모두 finding 위치뿐이었고, 기대 assessment와 불일치했다. 따라서 출력 완성도는 관찰상 나아졌지만 근거 활용 또는 보안 분석 품질 향상은 확인되지 않았다.

표본은 각 조건 1회뿐이며 실행 순서·캐시·로컬 자원 변동이 있다. 실제 `eval_duration` telemetry도 total과 모순된다. 추가 사례나 재시도는 이번 실험에서 수행하지 않았다. 최소 계약은 평가 전용으로 유지하고, 이를 프로덕션 AIReview나 provider 기본 계약으로 승격할 근거는 없다. 다음 단계에서는 최소 계약을 확장하기보다 정적 분석에서 source/sink 및 검증 조건에 대한 결정적 근거를 강화한 뒤 별도 합성 fixture로 재평가하는 편이 타당하다.
