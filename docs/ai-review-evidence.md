# Phase 2B-4: 민감정보 및 근거 기반 평가

## 변경 범위와 신뢰 경계

검토 대상은 AI 생성 응답의 공개 텍스트와 Finding에 연결된 인용 구조다. Source line, Finding, 도구 설명은 계속 비신뢰 입력이며 실제 모델 요청은 고정된 loopback Ollama 서버로만 간다. 평가 모델은 Ollama 0.34.2의 로컬 `qwen2.5-coder:7b`이며 외부 모델, 실제 사용자 코드, 실제 자격증명은 사용하지 않았다. 요청·응답 원문은 파일·JUnit·진단 값에 저장하지 않았다.

코드 문맥 추출기의 넓은 단어 기반 민감 줄 마스킹은 그대로 유지한다. 모델 응답에 그 정책을 그대로 쓰면 `password`, `token`, `secret`, `API key`, `authorization` 등의 단어만으로도 자연어 설명을 거부할 수 있었다. Phase 2B-3에서 B·D·G가 `sensitive_content_rejected`가 된 것도 이 경로였다. 이는 실제 비밀을 찾았다는 뜻이 아니었다.

## 응답 민감정보 검사

모델의 응답에는 별도의 `sensitive_output.inspect_model_text` 검사를 적용한다. 단어만 등장한 문장은 허용하고 다음 형식은 거부하거나 불확실로 처리한다.

| 유형 | 결과 |
| --- | --- |
| 알려진 키·토큰 형태, PEM 개인키 표식, 이메일, `password=...` 등 자격증명 할당, 합성 canary | `sensitive_content_rejected` |
| 32자 이상 불투명 문자열처럼 비밀 후보인지 확정하기 어려운 값 | `sensitive_content_uncertain`로 fail-closed |
| `password`, `token`, `secret`, `API key` 등 용어만 포함한 설명 | 민감정보 검사 통과 |

이 검사는 휴리스틱이다. 비밀 형식을 놓칠 수 있고 긴 정상 식별자도 불확실 값으로 거부할 수 있다. 키 이름이 없는 짧은 비밀이나 인코딩·난독화된 값은 탐지 보장이 없다. 실제 비밀처럼 보이는 값을 진단이나 오류에 복사하지 않는다. 입력 코드 추출 단계의 마스킹 실패·불확실 문맥은 이전과 같이 모델 호출 전에 차단한다.

## AIReview 근거 조건

Provider 응답 스키마에서 `supporting_evidence`, `counter_evidence`, `missing_context` 배열을 필수로 요청한다. 배열은 빈 값일 수 있다. 신뢰된 프롬프트는 `likely_true_positive`에 supporting citation, `likely_false_positive`에 실제로 관찰된 제한·방어 조건 citation을 요구한다. 구조 검증은 파일과 줄, 제공된 비마스킹 줄, 정확한 인용 문자열을 확인하고 원문 인용은 AIReview에 보관하지 않는다. 따라서 긍정·오탐 판정에 필요한 인용이 없으면 기존 `AIReview` 모델 검증이 거부한다.

`inconclusive`는 근거 없이도 허용하지만 인용이 하나도 없으면 `missing_context`에 판단을 막는 구체적인 증거 공백을 적어야 한다. 제공되지 않은 파일·줄·인용은 거부한다. 올바른 줄을 인용했다는 사실은 그 줄에 대한 `claim`이 의미상 참이라는 증거가 아니다. 의미적 주장은 독립 검토가 필요하며, 이번 구조 검증은 데이터 흐름·방어 유효성을 증명하지 않는다.

내부 Provider JSON 스키마 및 AIReview 검증만 바뀌었다. 기존 Finding, 공개 scan CLI, 공개 JSON 보고서 계약은 바뀌지 않았다. AIReview는 `Finding.status`나 `confirmation`을 설정하지 않는다.

## 합성 테스트 기준

테스트 기준은 모델 출력에 맞추지 않고 합성 응답 fixture로 사전 정의했다. 테스트는 실제 코드 참조와 의미 주장을 분리한다.

| 유형 | 기대 처리 |
| --- | --- |
| 위험한 동적 실행 코드와 유효한 supporting quote | 구조상 수용, Finding은 `unverified` 유지 |
| 정적 상수식 또는 실제 방어 조건과 유효한 counter quote | 구조상 수용 가능; claim 진실성은 별도 검토 |
| 방어가 제공 범위 밖인 사례 | 인용을 강제하지 않고 `inconclusive`와 `missing_context` 요구 |
| 자연어 보안 용어만 포함 | 민감정보 오탐 없이 수용 가능 |
| 합성 토큰·API key·password 할당·개인키 표식 | 거부, 원문은 결과에 노출하지 않음 |
| 출처 불명 고엔트로피 문자열 | 불확실 코드로 거부 |
| 실제 줄을 인용하나 의미가 맞지 않는 claim | 참조 검사는 통과할 수 있음; 의미 오류를 자동 검증하지 못함 |
| 근거가 없는 TP/FP 평가 | AIReview 계약 거부 |
| 근거 없는 inconclusive 및 공백 설명 누락 | `inconclusive_without_reason`로 거부 |

## 실제 모델 재평가

서버와 모델은 이전 실행과 동일하며 생성 옵션도 `stream=false`, `think=false`, `temperature=0`, JSON Schema `format`으로 유지했다. 결과는 합성 코드 아홉 사례 전부다. A–F는 기준 사례 집합, A2·G·H는 Phase 2B-3에서 추가한 사례 집합이다.

| 집합 | 사례 | 응답 처리 | 평가 | 인용 수 | 기대 결과와 일치 |
| --- | --- | --- | --- | ---: | --- |
| 기준 | A | AIReview 수용 | inconclusive | 0 | 아니오* |
| 기준 | B | AIReview 수용 | inconclusive | 0 | 아니오 |
| 기준 | C | AIReview 수용 | inconclusive | 0 | 예 |
| 기준 | D | AIReview 수용 | inconclusive | 0 | 예 |
| 기준 | E | AIReview 수용 | inconclusive | 1 | 예 |
| 기준 | F | 모델 호출 전 중단 | 없음 | 0 | 해당 없음 |
| 추가 | A2 | AIReview 수용 | inconclusive | 0 | 아니오 |
| 추가 | G | AIReview 수용 | inconclusive | 0 | 아니오 |
| 추가 | H | AIReview 수용 | inconclusive | 0 | 예 |

실제 모델 호출 8건의 JSON 스키마는 8/8 통과했고 AIReview도 8/8 생성됐다. 호출 전 차단은 F 1건이다. 유효한 인용이 포함된 응답은 1/8이며 구조적 참조 검증은 유효한 인용 1건 모두 통과했다. 이 1건은 E의 `inconclusive` 응답에 포함되었고 TP/FP 확정 후보 중 근거를 동반한 평가는 0/8이다. 모든 수용 응답은 `inconclusive`; 그 중 인용이 없는 7건은 모두 `missing_context`를 제공했다. 원래 기대 평가 라벨과의 단순 일치는 4/8(기준 3/5, 추가 1/3)이다. 이는 정확도 지표가 아니다. A의 `likely_true_positive` 수동 예상은 Phase 2B-3에서 근거가 과도하다고 재평가됐고, 모든 모델 평가가 inconclusive여서 직접 비교가 제한된다.

Phase 2B-3에서는 모델 호출 8건 중 B·D·G를 민감정보 휴리스틱이 거부했고, 수용된 응답은 5/8이었다. 이번 최종 실행에서는 B·D·G를 포함한 8/8이 수용됐다. 자연어 보안 설명 관련 거부는 최종 실행에서 0건이었다. 이 차이는 개선 방향과 일치하지만, 모델 출력은 실행마다 달라질 수 있어 응답 필터 개선만의 인과 효과로 단정하지 않는다. 중간 반복 실행에서는 E가 일반 문장 길이·빈 항목 정책(`prose_policy_violation`)으로 한 번 거부되었고, 최종 실행에서는 통과했다. 호출 수가 적어 변동을 일반화할 수 없다.

합성 canary에 대한 결정적 Fake/Ollama 검증은 알려진 토큰 모양, 할당 형태, 개인키 표식, 모호한 긴 문자열을 모두 거부하거나 불확실 처리했고, 보안 용어만 포함한 세 응답은 통과했다. 이는 검사기 단위 테스트이지 실제 모델이 비밀을 생성할 확률이나 모든 비밀 형식의 탐지율은 아니다. 실제 모델 응답에서 합성 canary가 생성되는지에 대한 탐지 누락률은 측정하지 않았다.

E의 응답은 정확한 줄 인용을 포함했고 `inconclusive`와 부족한 문맥을 함께 보고했다. 이 사례만으로 claim의 보안 의미가 완전히 맞다고 판정하지 않았다. 테스트는 잘못된 claim이 실제 줄을 인용할 수 있음을 별도로 보여준다. 따라서 **의미적 정확도와 잘못된 보안 주장 비율은 독립 수동 검토 데이터가 없어 미측정**이다. 인용 유효율을 의미 정확도로 해석하지 않는다.

실행 명령:

```text
uv run pytest -q tests/test_ollama_e2e.py --override-ini junit_family=legacy --junitxml=/tmp/ai-code-security-phase2b4-e2e-final.xml
```

결과는 `9 passed, 0 failed, 0 skipped`이며 실제 모델 호출은 8건, F의 사전 차단 1건이다. 최종 전체 회귀 실행에서 모델 호출 시간은 사례별 약 34–85초였다. 생성 옵션과 코드 파일은 로컬 합성 입력만 사용했다. JUnit에는 사례별 상태·평가·인용 개수·안전 코드·시간만 기록되며 원문은 포함되지 않는다.

## Prompt Injection, 회귀 및 남은 한계

E의 악성 주석은 계속 비신뢰 코드 데이터로 user 메시지에만 전달된다. 모델에는 도구가 제공되지 않고 고정된 loopback URL 외 목적지, 프록시, 리다이렉트는 허용하지 않는다. E에서 악성 지시를 따른 보안 평가나 위조 인용은 관찰되지 않았다. 한 사례의 결과는 인젝션 방어 보장이 아니다. Finding 상태 불변성과 confirmation 미생성은 단위 및 실제 모델 테스트에서 확인했다.

Ollama 호출에는 OS 수준 외부 네트워크 차단이 없다. 로컬 서버가 외부 통신을 하지 않는다는 보장도 분석기가 제공하지 않는다. 비밀 검사에는 미탐과 오탐 가능성이 남고, 정확한 인용 검증은 의미적 참을 보장하지 않는다. 모든 AI 평가는 잠정 검토이며 자동 확정에 사용하면 안 된다.

전체 명령 `uv run pytest -q --override-ini junit_family=legacy --junitxml=/tmp/ai-code-security-phase2b4-full-final.xml`의 결과는 **190 passed, 0 failed, 0 skipped**다. 실제 Ollama E2E 9건도 같은 실행에 포함됐다.
