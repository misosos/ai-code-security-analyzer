# AI 검토 계약과 신뢰 경계 (Phase 2B-1)

이 단계의 파이프라인은 `Finding → CodeContext Extractor → AIAnalysisRequest → FakeProvider → 응답 검증 → AIReview`이다. 실제 모델·HTTP·원격 서비스를 사용하지 않는다. 기존 `scan` CLI와 JSON 보고서에는 AI 검토 결과나 코드 조각을 추가하지 않는다.

## 입력과 출력

`AIAnalysisRequest`는 코드에 고정된 `trusted_instructions`와 `untrusted_finding`, `untrusted_context`, `untrusted_source_lines`를 별도 필드에 둔다. 후자에는 Semgrep 결과, 도구 설명, 마스킹된 코드와 주석이 포함된다. `source_trust_label=untrusted_source_code`, `external_transmission_allowed=false`를 명시한다. 요청은 메모리에서만 구성되며 저장·전송하지 않는다. 직렬화 크기는 최대 40 KB로 제한한다.

`ReviewProvider.generate(request) -> str`는 최소 내부 인터페이스다. 현재 공개 실행 함수 `run_fake_review`는 정확히 `FakeProvider`만 허용하며 고정 합성 JSON 또는 합성 예외를 반환한다. 실제 모델 제공자 구현이나 SDK는 없다.

`AIReview`는 `finding_id`, `assessment`, `summary`, `supporting_evidence`, `counter_evidence`, `insufficient_context`, `origin=fake_provider`로 구성된다. `assessment`는 `likely_true_positive`, `likely_false_positive`, `inconclusive` 중 하나다. 이는 **AI식 검토 후보**이며 `Finding.status`, `Finding.confirmation`, 실제 취약점 확정과 다르다. `AIReview`에는 `confirmation` 필드가 없고, 모델이 추가하면 거부한다. `ReviewOutcome`은 완료·문맥 부족·요청 거부·크기 초과·응답 검증 실패·Provider 실패를 구분하며 안전한 issue 코드만 제공한다.

Provider 응답은 최대 16 KB의 JSON으로 제한하고 Pydantic 스키마의 필수 필드, 자료형, 열거값, 추가 필드 금지를 확인한다. 근거는 역할별로 분리하며 파일 경로와 줄 번호가 현재 Finding 및 제공된 코드 문맥과 일치해야 한다. Provider가 제시한 짧은 인용문이 **마스킹되지 않은 해당 줄에 정확히 존재**해야 한다. 검증 후 인용문은 `AIReview`에 저장하지 않는다. 마스킹되거나 생략된 줄을 근거로 삼으면 거부한다. `redacted` 또는 `truncated` 문맥에서는 `inconclusive`, `insufficient_context=true`, 고정된 불충분 요약과 빈 근거 목록만 허용해 가려진 내용의 추정을 받아들이지 않는다. 일반적인 주변 줄 생략(`omitted`)만으로 모든 판단을 강제로 불충분 처리하지는 않는다.

이 검증은 참조가 입력에 존재한다는 **구조적 검사**다. 근거에 붙인 주장과 실제 보안 의미, 입력에서 위험 동작까지의 흐름, 오탐 여부는 증명하지 않는다. `summary`와 `claim`도 비신뢰 모델 출력이다. 명백한 비밀 후보·전체 코드 줄의 재출력을 거부하지만 휴리스틱 필터가 모든 민감정보를 탐지하지 못한다. 기존 공개 보고서와 로그에는 이 출력 및 코드 원문을 싣지 않는다.

## 프롬프트 인젝션과 향후 전송

코드와 주석의 “지침 무시”, 결과 조작, 비밀 출력, 도구 실행, 외부 전송 요구는 데이터일 뿐이다. Fake Provider는 도구·파일·네트워크 동작을 수행하지 않는다. 구분된 필드와 지침 문구만으로 향후 실제 LLM의 인젝션 저항성이 입증되지는 않는다.

Phase 2B-2 전에 실제 모델 사용 여부와 제공자, 전송할 데이터의 범위, 보존·삭제 정책, 사용자 명시적 승인, 추가 비밀정보 검토, 요청·응답 기록 정책을 결정해야 한다. 실제 모델을 붙인 뒤에는 프롬프트 인젝션 공격 테스트와 의미적 근거 검증 기준을 별도로 마련해야 한다. Fake Provider 테스트는 AI 정확도나 공격 방어율의 측정값이 아니다.
