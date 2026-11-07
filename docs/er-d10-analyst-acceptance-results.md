# ER-D10 분석가 수동 수용 결과 기록

`SAFARI_MANUAL_ACCEPTANCE_PENDING` / `ANALYST_ACCEPTANCE_PENDING`

핵심 이해 평가 A01~A07의 종합 수용은 아직 대기 중이다. 아래에 후속 사용자 진술로 확인된 UI 동작을 별도로 보존한다. 자동화, 과거 ER-C3G 사용자 수용, 검수 환경 준비를 이번 수동 PASS로 사용하지 않는다.

## 2026-11-07 사용자 직접 보고

출처는 `DIRECT_USER_ATTESTATION` / `USER_REPORTED_MANUAL_SAFARI_ACCEPTANCE`다. 사용자가 보고한 검수일은 2026-11-07이며 실제 macOS Safari 수동 조작에 대한 진술이다. 실행 SHA, Safari/macOS 상세 버전 및 원본 캡처는 별도 제출되지 않았다. Codex가 해당 Safari 조작을 직접 관찰한 것은 아니다. 아래 PASS는 진술한 UI 동작에만 적용한다.

| 사용자 확인 동작 | 수동 결과 | 출처 |
| --- | --- | --- |
| 새로운 검사 실행 및 Finding 표시 | PASS | USER_ATTESTED |
| 부분 완료 검사 결과의 증거 기준 저장 | PASS | USER_ATTESTED |
| 부분 완료 검사 비교 제한 | PASS | USER_ATTESTED |
| 비교 기준 해제 | PASS | USER_ATTESTED |
| 조사 증거 해제 버튼과 안내 표시 | PASS | USER_ATTESTED |
| 조사 증거 해제 직후 현재 화면의 Finding 유지 | PASS | USER_ATTESTED |
| 새로고침 시 검사 시작 화면 복귀 | PASS | USER_ATTESTED |

서버 무효화, 기존 Handle 재사용 거부, 해제 실패 처리, 최대 15분 TTL은 이 사용자 진술로 확인되지 않았다. [후속 자동 검증](er-d10-evidence-revocation-followup.md)과 구분한다. A01~A06의 설명 이해와 자유 응답, A07의 전체 Map 무효화 조건도 위 진술만으로 PASS로 확대하지 않는다. 후속 수정 코드에 대한 실제 Safari 재검수는 아직 수행되지 않았다.

## 검수 정보

| 항목 | 값 |
| --- | --- |
| 검수 수행일·보고일 | 사용자 보고 수행일 2026-11-07; 별도 보고 시각 NOT_RECORDED |
| 실제 실행 SHA | NOT_RECORDED — 실행기 터미널의 SHA와 추적 파일 변경 여부를 받아 기록 |
| 기록 기준 SHA | `6fc6ce98b914d3727296b539b4e27a4f3f186cd0` |
| Safari 상세 버전 | NOT_RECORDED |
| macOS 상세 버전·기기 | NOT_RECORDED |
| 실제 사용자 조작 | 위 7개 UI 동작에 대한 직접 진술 |
| 유도·도움 제공 여부 | NOT_RECORDED |
| 민감정보가 제거된 캡처 | NOT_PROVIDED |

## 핵심 수용

모든 조건이 확인된 행만 PASS로 변경한다. 복합 항목은 실제 확인한 범위를 적고 나머지 조건은 NOT_TESTED로 남긴다. 사용자 답변은 의미를 확대하지 않고 원문 또는 명시적으로 구분한 요약으로 보존한다. 자동화에서 확인한 서버 동작은 수동 답변 칸에 넣지 않는다.

| ID | 사용자 확인 범위 | 수동 상태 | 실제 조작·사용자 응답·근거 |
| --- | --- | --- | --- |
| A01 | Finding 미관찰과 해결 여부 구분 | NOT_TESTED | NOT_REPORTED |
| A02 | 경로 제외와 전체 검사 완료 구분 | NOT_TESTED | NOT_REPORTED |
| A03 | 선택 규칙 바이트와 전체 로딩 규칙 구분 | NOT_TESTED | NOT_REPORTED |
| A04 | Finding별/전체 Gap, 미수집·미검증 영역 찾기 | NOT_TESTED | NOT_REPORTED |
| A05 | 관찰에 연결된 다음 작업을 스스로 선택하고 이유 설명 | NOT_TESTED | NOT_REPORTED |
| A06 | Partial/INCOMPARABLE 의미 구분 | NOT_TESTED | NOT_REPORTED |
| A07 | 증거 해제 UI 조작과 Map 무효화 확인 | NOT_TESTED | NOT_REPORTED |

A07의 이전 Session 재평가 거부는 [자동 회귀 기록](er-d10-security-regression.md)의 HTTP 404 근거와 구분한다. UI 조작만으로 서버 메모리의 즉시 완전 삭제를 주장하지 않는다. 사용자가 Handle을 채팅이나 문서에 제출할 필요는 없다.

### A05 자유 응답

| 시나리오 | 사용자가 선택한 작업 | 사용자가 설명한 관찰 근거 | 유도·추가 도움 |
| --- | --- | --- | --- |
| A/B → A/C | NOT_REPORTED | NOT_REPORTED | NOT_RECORDED |
| Skip / Partial | NOT_REPORTED | NOT_REPORTED | NOT_RECORDED |

## 추가 화면·접근성 수용

| 항목 | 실제 Safari 수동 상태 | 근거 |
| --- | --- | --- |
| 1440×900 | NOT_TESTED | |
| 1024px | NOT_TESTED | |
| 768px | NOT_TESTED | |
| 390px | NOT_TESTED | |
| 320px | NOT_TESTED | |
| Safari 실제 200% 확대 | NOT_TESTED | |
| 키보드 주요 흐름 및 Focus | NOT_TESTED | |
| 비활성 버튼·오류 안내 | NOT_TESTED | |
| 실제 TTL 만료 안내 | NOT_TESTED | |
| Gap Map 위계·Finding 상세 가독성 | NOT_TESTED | |
| VoiceOver | NOT_TESTED | |
| iOS Safari | NOT_TESTED | |

## 결함과 수용 결정

사용자 보고 결함은 **부분 검사 기준 저장 직후 정상 비교가 가능해 보이는 안내 충돌**이며 P2(설명 혼동)로 분류했다. 부분 기준 저장 후 새 검사 안내와 부분 비교 차단이 동시에 표시됐다. [후속 수정·검증](er-d10-evidence-revocation-followup.md)에서 부분 기준에 맞는 안내로 수정하고 자동 검증했다. 수정 후 실제 사용자 Safari 재검수는 `NOT_TESTED`다. 그 밖의 P0/P1 사용자 보고는 없으며, 미보고를 결함 부재나 사용자 PASS로 보지 않는다.

`ER_D10_SAFARI_ANALYST_ACCEPTANCE_GO`는 아직 부여하지 않았다. 필수 수동 항목 PASS, 실제 실행 SHA·환경, 이해·후속 선택 확인 및 P0/P1 미해결 없음이 확인된 뒤 판정한다. 사용자 효과의 정량 개선과 운영 승인은 별도이며 현재 `NOT_ESTABLISHED`, `NOT_APPROVED`다.
