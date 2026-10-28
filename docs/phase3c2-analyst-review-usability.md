# Phase 3C-2: Analyst Review 사용성 및 의미 정확성 평가

## 평가 목적과 범위

기준 커밋은 `f556e7f4447a8edb17f4cd420db95dd23449f50b`이다. 이 평가는 `scan --format review`가 이미 검증된 Semgrep 결과와 제한 사항을 정확하고 과장 없이 전달하는지 확인한다. 탐지 기능, Gate/Consumer 정책, Finding 상태를 변경하거나 보안 탐지 성능을 평가하지 않는다.

평가를 두 갈래로 분리한다.

1. **자동 정보 전달 검증:** 사전에 고정한 의미 정책과 합성 사례를 사용해 필수 설명, 금지된 주장, 누락·생략 안내, 비밀정보 비노출을 확인한다.
2. **사람 대상 이해도 평가 준비:** 참가자용 질문지와 별도 채점표를 제공한다. 이번 Phase에서는 참가자에게 질문지를 시행하지 않았다.

실제 코드 대신 합성 Semgrep 결과와 기존 A–L 합성 fixture를 사용한다. 실제 Ollama 추론, 외부 서비스, 사용자 저장소는 사용하지 않는다.

## 사전 고정한 의미 정책

기대 결과는 Review View 출력을 복사해 만들지 않고, 화면이 전달해야 하는 사실의 범위를 먼저 정해 테스트 데이터와 질문지에 고정했다.

| 화면 상태 | 허용되는 설명 | 금지되는 해석 |
| --- | --- | --- |
| completed | Semgrep 검사가 정상 종료됨 | 코드가 안전함, 취약점이 없음, 모든 문제가 검사됨 |
| partial | 일부 검사 및 개별 후보가 보고됨 | 전체 검사 완료, 누락 영역의 안전성 |
| 높은 Semgrep severity | 도구가 높은 severity로 분류함 | 실제 악용 가능성 또는 취약점 검증 완료 |
| taint match | 신뢰된 규칙에 따른 매치가 보고됨 | 실제 Source 위치, 완전한 경로, 런타임 공격 성공 |
| Source/Sink 위치 unavailable | 해당 위치가 현재 구조화 근거에 없음 | 위치가 없으므로 데이터 흐름이 없음 |
| trace absent | trace가 결과에 제공되지 않음 | 흐름 부재 또는 오탐 |
| unverified | 검토 후보이며 취약점/오탐 모두 미확정 | 취약점 확정 또는 오탐 확정 |
| analyst checklist | 분석가가 직접 수행할 다음 확인 작업 | 검증이 이미 완료됐거나 결론이 정해짐 |
| completed, 0 findings | 이 검사에서 보고된 Finding이 없음 | 대상 코드가 안전함 |

## 확인한 문구와 변경

코드 수준의 수동 검토와 합성 화면 출력을 비교했다.

- 카드의 `심각도: high`는 도구 분류임을 덜 분명하게 전달할 수 있었다. `Semgrep 심각도 분류: high (실제 악용 가능성 판정은 아님)`으로 구체화했다. 검증 상태는 별도 줄에서 다룬다.
- `Finding 상태: unverified`는 내부 enum을 그대로 노출했다. `검증 상태: 미검증 후보 (취약점·오탐 모두 미확정)`으로 바꿨다. 기존 Finding 객체의 상태 값은 변경하지 않는다.
- trace 부재 설명이 “trace가 없습니다”에서 끝나면 경로가 없다는 뜻으로 잘못 읽힐 여지가 있었다. `흐름이 없다는 뜻은 아닙니다`를 추가했다.
- 완료된 0건 결과에는 안전성 주의 문구가 두 번 나왔다. 공통 해석 제한에 한 번만 남겼다.
- 바이트 상한 대체 출력은 표시된 상세와 생략된 상세 수를 설명하지 않았다. 이제 전체 수, 표시 0건, 생략 수, 개별 상태를 확인할 수 없다는 점을 포함한다. Finding 수 상한에 의한 일반 생략도 생략 항목을 안전하다고 볼 수 없다고 명시한다.

체크리스트는 “실제 입력 출처를 코드에서 확인”, “위험 함수에 전달되는 값 확인” 등 행동 지시형 문장이다. 이 문구는 사실 판정이 아니라 직접 수행할 작업으로 표시된다. 의미 변경이 필요한 다른 문구는 발견하지 않았다. 입문자에게 낯선 `taint`에는 “정의된 입력 흐름을 검사하는 규칙”이라는 짧은 안내를 붙였다. Source, Sink, Finding, Trace 개념을 동의어로 바꾸지는 않았다.

## 합성 평가 시나리오

각 기대값은 실행 전에 고정했다. S1–S16은 기존 review 테스트와 새 의미 계약 테스트를 합쳐 점검했다.

| ID | 사례와 기대 | 자동 검증 위치 |
| --- | --- | --- |
| S1 | 정상 taint 매치: 규칙 매치만 사실로 표시; 전체 경로·취약점 확정 금지 | `test_fixed_taint_policy_oracle_covers_supported_and_prohibited_meanings`, Semgrep E2E |
| S2 | 일반 pattern: 일반 패턴 분류; taint 매치 주장 금지 | `test_pattern_and_zero_finding_oracles_do_not_overstate_results` |
| S3 | completed, 0건: 완료와 0건 표시; 안전 보장 금지, 안전 주의 1회 | 같은 테스트 |
| S4 | high severity, unverified: 도구 등급과 검증 상태 분리 | `test_severity_verification_and_finding_count_are_distinct` |
| S5 | Source 위치 unavailable: 확인 불가를 표시; 선언과 위치 혼동 금지 | S1 oracle 및 `test_review_shows_only_consumer_supported_claims_and_fixed_review_tasks` |
| S6 | Sink 인자 위치 unavailable: 매치 위치를 Sink 인자로 승격하지 않음 | 위와 동일 |
| S7 | trace absent: 구조화 trace 부재와 흐름 부재를 구분 | S1 oracle 및 제한 claim 테스트 |
| S8 | Sanitizer 선언만 존재: 실제 매치/효과 검증 금지 | `test_unclassified_and_sanitizer_claims_remain_restricted` |
| S9 | partial: 부분 상태 유지, Gate가 허용한 개별 매치만 표시 | `test_partial_and_failed_scan_have_distinct_fixed_semantics` |
| S10 | failed: 확인 사실/지원 claim을 표시하지 않음 | 같은 테스트 및 `test_review_never_shows_claims_from_nonreviewable_scan` |
| S11 | Consumer 오류: 해당 카드만 사실을 비우고 고정 코드 표시 | `test_consumer_failure_never_becomes_a_supported_review_claim` 및 기존 격리 테스트 |
| S12 | 규칙 해시 불일치: 분류를 미검증으로 낮추고 해시 불일치 표시 | `test_unclassified_and_sanitizer_claims_remain_restricted` |
| S13 | 다중 Finding: 순서 번호이며 위험 순위 아님 | `test_review_output_limit_reports_omitted_findings` |
| S14 | Finding/바이트 출력 제한: 총계와 생략 수·상태 한계 표시 | `test_multiple_findings_and_output_omission_preserve_totals`, `test_byte_limit_fallback_states_exact_omission_counts` |
| S15 | 제어문자가 있는 상대 경로: 터미널 제어 효과 없이 escape | `test_special_paths_and_semgrep_canary_do_not_reach_review_output` 및 기존 경로 테스트 |
| S16 | Semgrep message/lines의 합성 canary: 출력에 나타나지 않음 | 같은 테스트 및 실제 Semgrep E2E |

정확 문자열의 자동 검증은 고정 템플릿의 회귀 검증이다. 자연어의 모든 해석 가능성을 증명하지 않으므로 참가자 평가를 대체하지 않는다.

## 자동화된 평가 결과

테스트는 고정 의미 oracle의 필수·금지 문구, 상태와 Finding 유형, 개별 제한 사항, Consumer 거부, 민감정보 비노출, 표시·생략 개수 및 바이트 상한을 확인한다. 새 독립 의미 테스트의 통과 수는 실행 로그를 기준으로 최종 보고한다.

별도 지표의 해석:

- **금지 주장 출력:** 테스트한 고정 합성 시나리오에서 금지 phrase 발생 수로 보고한다. 자연어 의미 전체의 안전성률이 아니다.
- **제한 누락:** 각 사례의 사전 고정 필수 제한 phrase가 출력에 있는지로 확인한다.
- **Claim 매핑:** Gate/Consumer가 허용한 claim은 확인 사실에, 나머지는 제한 영역에만 나타나는지 확인한다.
- **개인정보 노출:** 합성 canary 및 제어문자 대조군의 정확 일치·escape 여부를 검사한다.
- **출력 생략:** 전체 Finding 수, 표시 수, 생략 수, 생략 상태의 불확실성을 확인한다.

## 실제 Semgrep 검증

Semgrep OSS 1.182.1에서 기존 합성 taint 13건과 baseline pattern 11건의 Review View 연결을 검증한다. 기존 E2E가 실제 결과 수, Consumer 검증 통과 수, taint/pattern 분류, restricted 경로 제한, Finding 상태, canary 비노출을 확인한다. 사람의 의미 해석은 이 E2E로 측정하지 않는다.

## 사람 대상 평가 준비 및 상태

참가자용 [질문지](phase3c2-participant-questionnaire.md)와 별도 [채점표](phase3c2-scoring-key.md)를 준비했다. 진행자는 `uv run python tests/review_usability_examples.py --case all`로 다섯 개의 전체 Review View 화면(taint, pattern, partial, failed, zero)을 재생성해 보여줄 수 있다. 이 도구는 합성 Semgrep JSON 메타데이터만 사용하고 실제 scan/LLM 호출을 하지 않는다. 질문은 동일한 합성 검토 화면을 읽고 답하도록 구성했다. 권장 참가자 층은 보안 입문자, 정적 분석 경험 개발자, 보안 분석 경험자다. 실제 모집·참가·응답은 하지 않았다.

따라서 사람 대상 이해도, 만족도, 응답 시간은 **NOT_TESTED**이며 수치가 없다. 향후 소규모 형성 평가를 할 때 참가자 층별 응답을 따로 기록하고, 식별자·이메일·실제 코드 없이 익명 답변과 최소한의 배경 범주만 수집한다. 평균 응답 시간 등의 측정값을 실제 기록 없이 만들어서는 안 된다.

## 수동 검토 범위와 제한

수동 검토는 템플릿, 출력 순서, 반복 제한 사유, 50건 Finding cap, 512 KiB 출력 cap, path/control escaping, 실패 카드 분리를 대상으로 했다. 중복 사유는 한 카드에서 한 번만 보여주고, 생략된 항목 수와 개별 검증 상태를 확인할 수 없다는 설명을 추가했다. 새 대화형 UI는 없고 체크리스트 완료 기록도 없다. 대량 결과에서의 실제 가독성과 초보 사용자 이해도는 확인하지 않았다.

재현 스크립트가 같은 renderer에서 생성한 합성 화면 크기는 taint 55줄/3,926바이트, pattern 46줄/2,914바이트, partial 56줄/3,884바이트, timeout 37줄/1,462바이트, zero 19줄/542바이트였다. 이 값은 단일 합성 예의 출력량 측정이며 성능 벤치마크나 운영 SLA가 아니다. 한 카드가 여전히 길고 pattern에도 taint 관련 제한이 표시되어 다소 밀도가 높다. 현재는 제한 정보를 잃지 않도록 보존했으며, 실제 참가자 평가에서 어느 제한이 불필요하거나 핵심을 가리는지 확인한 뒤 후속으로 다듬는다.

자동화는 고정 입력·언어·템플릿 범위에 한정된다. Semgrep 규칙 및 소스 파일의 실행 시점 불변성을 증명하지 않으며, 구조화 claim이 실제 코드 의미상 올바른지를 자동 판정하지 않는다. OS 수준 네트워크 격리도 제공하지 않는다. 기존 CI의 Python·Semgrep 두 job은 변경하지 않는다.

실행 명령과 통과·skip 수는 해당 커밋의 최종 보고에 기록한다. 기본 pytest에서는 Ollama opt-in을 설정하지 않으며 사람 대상 평가를 자동화 테스트 결과와 혼합하지 않는다.
