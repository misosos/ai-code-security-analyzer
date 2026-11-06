# ER-D8 Security Evidence Gap Map

## 목적과 입력

조사 결과에서 관찰과 미확인 사항, 사람이 수행할 후속 확인을 한 영역에 모은다. `finding-disappearance-evaluation/v1`, 선택적으로 `rule-bytes-comparison/v1`과 두 검사 응답을 프런트엔드에서 투영한다. 서버 저장소, API, 원시 Manifest, Digest 또는 소스 수집은 추가하지 않는다.

## 결합과 생성

두 응답과 서로 다른 Run Handle, 대상·프로필·모드, 기존 비교 조건, Finding ID·범주·건수 및 부분 검사 상태를 확인한다. DTO는 기존 닫힌 parser로 재검증한다. 기준에서만 관찰된 Finding의 경로 관찰과 Skip 가설이 현재 평가기 계약에 맞지 않으면 Map을 표시하지 않는다. 일반 비교가 부분 검사 외 이유로 차단되면 우회하지 않는다. Rule Bytes 모드는 같은 Session의 두 응답이 모두 확인될 때만 Map을 완성한다. 새 검사·기준 교체·토큰 삭제·옵션 변경·해제 등은 기존 요청 순번과 증거 상태를 무효화한다.

브라우저는 각 검사 요청 시작 시각을 단조 시계와 벽시계로 기록하고 둘 중 하나가 15분을 넘으면 표시를 무효화한다. 요청이 시작된 시각은 서버 Run 생성보다 이르므로 이 시한은 보수적인 클라이언트 표시 제한이다. 서버 TTL을 읽거나 증거의 유효성을 보증하는 값은 아니며 실제 평가 때 서버가 최종 확인한다. 화면이 다시 활성화될 때도 시한을 검사한다.

## 상태와 범위

Map의 닫힌 상태는 `OBSERVED`, `NOT_REPORTED`, `NOT_COLLECTED`, `UNAVAILABLE`, `UNVERIFIED`, `INCOMPARABLE`, `CONFLICTING`, `NOT_APPLICABLE`이다. 경로가 목록에 없다는 관찰은 미수집·사용 불가·미검증과 구분한다.

- Finding ID 집합의 변화는 검사 전체의 관찰이다. ID 일치는 코드 또는 취약점의 의미상 동일성을 뜻하지 않는다.
- 기준 검사에서만 관찰된 Finding의 경로 관찰과 Skip 가설은 그 Finding에만 적용한다. 제외 상세 원문이 DTO에 없으므로 특정 Ignore 파일이 원인이라고 추측하지 않는다.
- Rule Bytes의 같은/다른 바이트는 두 실행에 제공한 선택된 단일 규칙 파일 사본에 한정한다. OFF는 요청하지 않은 상태이고 `UNVERIFIED` 응답과 다르다. 주석만 달라도 바이트가 다를 수 있다.
- 기존 Evaluation v1의 `rule_bytes_unverified`는 그 계약의 범위를 설명한다. 별도 Rule Bytes 결과가 있어도 전체 loaded rule inventory와 실제 적용은 여전히 미검증이다.
- Source Snapshot 미수집, Scope 완전성 미검증 및 취약점 해결 판단 불가는 유지한다. `PATH_REPORTED_SCANNED`는 전체 규칙 적용 완료의 증거가 아니다.

후속 작업은 비교 불가, 해당 Finding의 경로, 규칙 바이트 변화, 소스 변경 기록, 규칙·범위 한계 순으로 결정적으로 배치하고 중복을 제거한다. 이는 분석 작업 순서이며 위험 순위가 아니다. 작업은 제안이며 자동 실행되지 않는다.

## UI·개인정보·호환성

기존 조사 패널에 검사 전체 증거, Finding별 상세, 후속 작업을 접을 수 있는 영역으로 둔다. 상태는 색상뿐 아니라 텍스트로 표시한다. 기존 Evaluation, 비교기와 분석가 검토·Export는 유지한다. 원시 Digest, Token, Handle, 원시 출력, 내부 절대 경로를 Map에 추가하지 않는다. 기존 공개 계약을 바꾸지 않으므로 롤백은 프런트엔드 투영 및 표시 코드를 제거하면 된다.
