# ER-D6 — 공개 Projection 후속 결정

## 현재 결정

이번 private 실행은 선택된 단일 baseline YAML의 사본 바이트를 두 독립 Semgrep 호출과 묶어 비교할 수 있다. 결과는 실행에 제공한 파일 바이트의 동일성만 말한다. loaded rules의 동일성, 특정 규칙 적용 완료, Finding 소멸 원인 또는 취약점 해결은 여전히 미검증이다.

공개 API와 UI는 구현하지 않았다. 기존 Manifest v1과 Evaluation v1의 필드·의미를 그대로 유지하고 `rule_bytes_unverified`, `loaded_rule_identity_unverified`도 유지한다. private 결과는 별도 객체이며 Registry에 저장되지 않는다.

## 공개 전 설계 대상

1. private 실행의 ScanResponse 및 내부 Run Reference와 byte 관찰을 원자적으로 결합하고, 두 Run의 target/profile/invocation/version과 위변조를 검증한다.
2. Registry 직렬화의 닫힌 필드 집합, 개별·전체 byte cap, 절대 TTL, Release, 동시 평가 및 재시작 소멸을 새 증거에도 적용한다. Digest는 원문 API/로그/Export에 내보내지 않는다.
3. Manifest v1은 digest를 보유하지 않는다. 확장에는 별도 version 또는 독립 versioned record가 필요하다. Evaluation v1의 closed DTO에 새로운 비교 상태를 추가하려면 별도 version 및 구버전 호환·마이그레이션 검토가 필요하다. 어느 버전도 이번 단계에서 변경하지 않았다.
4. 공개 후보는 `SAME_SELECTED_BYTES`, `DIFFERENT_SELECTED_BYTES`, `UNVERIFIED`, `INCOMPARABLE`처럼 digest 없는 닫힌 상태와 제한 문구다. 상태의 정확한 수집 시점과 실패 의미를 함께 표시해야 한다.
5. `loaded_rule_identity_unverified`는 유지한다. 사본 비교만으로 기존 `rule_bytes_unverified`를 제거할 수 있는지 새 계약과 운영 신뢰 경계에서 별도로 결정한다.
6. 동일 사용자에 의한 파일 교체, config 상대 참조, PATH 및 subprocess 환경, 플랫폼 차이, Registry 메모리와 개인정보 영향에 대한 시험이 필요하다.

## 마이그레이션과 롤백

기존 v1 세션에는 byte 관찰이 없으므로 새 버전은 이를 `UNVERIFIED`로 취급해야 한다. 새로운 기록·API를 활성화하기 전 strict serializer/parser와 무결성·TTL·Release 테스트를 통과해야 한다. 롤백은 신규 기록을 발급하지 않고 기존 v1 결과를 보존하는 방식으로 설계한다. 기존 Run에 비어 있는 digest를 정상 동일성으로 간주하거나 과거 데이터를 조용히 재해석하지 않는다.

## 상태

- ER-D7 공개 Projection: 설계 및 호환성 Gate 필요.
- 다중 Worker·다중 사용자: 미지원.
- 운영 배포: `NOT_APPROVED`.
- 취약점 자동 해결 판정: 미지원.
