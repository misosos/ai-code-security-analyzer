# Phase 8H — Safari 사용자 수용 결과 기록

## 검수 환경

| 항목 | 기록 |
|---|---|
| 검수 날짜 | 실제 사용자 검수 전 — 미기록 |
| 검수자 | 미기록 |
| macOS 버전 | `macOS 15.7.7 (24G720)` — 자동화 실행 호스트 정보이며 Safari 수동 검수 증거가 아님 |
| 실제 Safari 버전 | 미기록 — 이번 작업에서 Safari 앱 수동 조작 안 함 |
| 화면 해상도/창 크기 | 미기록 |
| 확대 설정 | 미기록 — 실제 Safari 200% 확대 미검증 |
| 사용한 합성 프로젝트 | 자동 QA smoke에서 프로젝트 A/B 사용. 실제 Safari 사용자 검수는 미실행 |
| 스크린샷/증거 | 없음 — 실제 Safari 캡처를 만들지 않음 |

## 사용자 검수 항목

다음 상태는 자동 Chromium, WebKit 또는 QA smoke 결과를 Safari 결과로 옮기지 않고 모두 `NOT_TESTED`로 둔다. 검수자는 실제 결과와 증거를 확인한 뒤 직접 갱신한다.

| # | 검수 항목 | 상태 | 실제 관찰/재현 절차 | 브라우저·크기·배율 | 증거 |
|---:|---|---|---|---|---|
| 1 | Safari에서 QA 로컬 서비스 열기 및 API 연결 상태 확인 | NOT_TESTED |  |  |  |
| 2 | 프로젝트/규칙 선택, 토큰 입력, 검사 실행 | NOT_TESTED |  |  |  |
| 3 | 실제 Semgrep Finding 목록, 상세 근거 및 제한 확인 | NOT_TESTED |  |  |  |
| 4 | Finding별 검토 상태와 메모 작성 및 독립성 확인 | NOT_TESTED |  |  |  |
| 5 | 분석가 상태와 Semgrep 검증 상태의 의미 구분 확인 | NOT_TESTED |  |  |  |
| 6 | Markdown 보고서 다운로드와 메모 포함 동의 확인 | NOT_TESTED |  |  |  |
| 7 | JSON 백업 다운로드, 메모 제외/포함 및 취소 확인 | NOT_TESTED |  |  |  |
| 8 | 같은 문맥 JSON 미리보기와 Finding별 수동 적용 확인 | NOT_TESTED |  |  |  |
| 9 | 다른 프로젝트 문맥의 JSON 복원 차단 확인 | NOT_TESTED |  |  |  |
| 10 | 새 검사/결과 삭제의 확인 및 취소 흐름 확인 | NOT_TESTED |  |  |  |
| 11 | 실제 Safari 페이지 확대 200%에서 주요 화면 및 작업 확인 | NOT_TESTED |  |  |  |
| 12 | Safari 키보드 전용 조작 및 네이티브 선택창 확인 | NOT_TESTED |  |  |  |
| 13 | 실제 iOS Safari 기기에서 화면과 탐색 확인 | NOT_TESTED |  |  |  |
| 14 | 실제 VoiceOver로 랜드마크, 이름, 상태 메시지 확인 | NOT_TESTED |  |  |  |
| 15 | 디자인, 가독성, 사용 흐름에 대한 최종 사용자 평가 | NOT_TESTED |  |  |  |

## 최종 수용 판단

- 사용자 명시적 승인: 대기
- 실제 Safari 확인 항목: 완료된 항목 없음
- 미검증 항목: 15개 전체
- 상태: `SAFARI_USER_ACCEPTANCE_PENDING`
- 중요 결함/수정 요청: 사용자가 실제로 확인한 뒤 기록
