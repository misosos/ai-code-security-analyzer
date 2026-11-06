# ER-D7 Contract Compatibility

## 버전 관계

- `scan-evidence-manifest/v1`: 필드와 기존 상태 의미 불변. 새 invocation 식별자만 closed allowlist에 추가했다.
- `finding-disappearance-evaluation/v1`: 필드, limitation 및 판단 의미 불변.
- `investigation-evidence-registry/v1`: 기존 canonical Response/Manifest serialization 불변. Rule Bytes는 직렬화 문서에 삽입하지 않는 bounded in-memory sidecar다.
- `rule-bytes-observation/v1`: 서버 내부 전용이며 HTTP 입력·출력에 사용하지 않는다.
- `rule-bytes-comparison/v1`: Digest 없는 equality projection이다.

기존 Run과 일반 v2 Run에는 sidecar가 없다. Rule Bytes projection 요청 시 필요한 실행 문맥이 아니면 `INCOMPARABLE`, 직접 바이트 근거가 없거나 검사가 partial이면 `UNVERIFIED`다. 과거 Run을 같은 바이트로 추정하지 않는다.

## Strict Serialization과 오류

신규 요청은 기존 closed `InvestigationScanRequest`와 `InvestigationEvaluateRequest`만 사용한다. 응답은 exact Pydantic/TypeScript parser 필드를 요구한다. 알려지지 않은 상태, limitation, field 또는 version은 거부한다.

인증·Host·Origin·JSON body cap·CORS·rate limit은 `/api/v2` 공통 경계를 통과한다. 만료·Release는 `404 evidence_unavailable`, binding 문제는 `409 binding_rejected`, single-flight 충돌은 `409 evaluation_busy`, 용량 초과는 `429 resource_limit`의 기존 고정 매핑을 사용한다.

## TTL과 Release

sidecar는 별도 Handle을 만들지 않는다. Run Handle의 수명과 원자적으로 결합되고 Session은 두 Run보다 오래 살 수 없다. Session Release는 참조를 제거하고, 그 뒤 Run Release가 sidecar까지 제거한다. 브라우저 종료 시 전송 성공은 보장하지 않으며 최대 15분 TTL이 최종 정리 한계다.

## 마이그레이션 제한

기존 Evaluation v1의 `rule_bytes_unverified`를 새 projection 결과로 제거하지 않는다. 선택 파일의 byte equality와 loaded rules identity는 별개다. 향후 통합된 Evaluation 계약이 필요하면 새 버전과 독립 마이그레이션 Gate가 필요하다.
