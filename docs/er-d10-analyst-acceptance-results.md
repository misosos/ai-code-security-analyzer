# ER-D10 분석가 수동 수용 결과 기록

`SAFARI_MANUAL_ACCEPTANCE_PENDING` / `ANALYST_ACCEPTANCE_PENDING`

이 파일은 사용자 응답을 받기 전의 미수행 기록이다. 자동화, 과거 ER-C3G 사용자 수용, 검수 환경 준비를 이번 수동 PASS로 사용하지 않는다. [계획](er-d10-safari-manual-acceptance-plan.md)에 따라 실제 사용자가 조작하고 결과를 제공한 뒤 갱신한다.

## 검수 정보

| 항목 | 값 |
| --- | --- |
| 검수 수행일·보고일 | NOT_RECORDED |
| 실제 실행 SHA | NOT_RECORDED — 실행기 터미널의 SHA와 추적 파일 변경 여부를 받아 기록 |
| 기록 기준 SHA | `6fc6ce98b914d3727296b539b4e27a4f3f186cd0` |
| Safari 상세 버전 | NOT_RECORDED |
| macOS 상세 버전·기기 | NOT_RECORDED |
| 실제 사용자 조작 | NOT_REPORTED |
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

사용자 보고 결함: `NOT_REPORTED`. 미보고는 결함 부재나 사용자 PASS가 아니다. 결함을 받으면 P0(잘못된 보안 판단·유출), P1(진행 불가·결합·상태), P2(설명·접근성), P3(시각·편의)로 분류하고 기대/실제, 안전한 재현 단계, 수정·재검수 상태를 기록한다.

`ER_D10_SAFARI_ANALYST_ACCEPTANCE_GO`는 아직 부여하지 않았다. 필수 수동 항목 PASS, 실제 실행 SHA·환경, 이해·후속 선택 확인 및 P0/P1 미해결 없음이 확인된 뒤 판정한다. 사용자 효과의 정량 개선과 운영 승인은 별도이며 현재 `NOT_ESTABLISHED`, `NOT_APPROVED`다.
