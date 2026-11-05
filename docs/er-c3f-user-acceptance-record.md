# ER-C3F 사용자 수용 기록

ER-C3G에서 핵심 조사 흐름에 대한 사용자 수용을 기록했다. 이 기록은 사용자 보고와 대화에 제공된 화면 캡처를 근거로 하며, 각 세부 항목의 범위는 아래에 따로 적는다. 허용 상태는 `NOT_TESTED`, `PASS`, `FAIL`, `BLOCKED`다.

- 결과 보고일: 2026-11-05
- 실제 검수 수행일: `NOT_RECORDED`
- 브라우저: macOS Safari; 상세 버전: `NOT_RECORDED`
- macOS 상세 버전: `NOT_RECORDED`
- 기록 작성 기준 SHA: `a52b2ec660f33592aaaa7b40f524e357283ab4c4`
- 실제 실행 SHA: `EXECUTED_SHA_NOT_INDEPENDENTLY_VERIFIED`
- 수용 방법: 사용자의 직접 수동 조작
- 수용 결과: 핵심 조사 흐름 PASS
- 출처: `USER_REPORTED_MANUAL_SAFARI_ACCEPTANCE` / `DIRECT_USER_ATTESTATION`
- 화면 캡처: 사용자가 대화에 제공함. 저장소에 복사하거나 별도 실행 로그가 제공됐다고 주장하지 않는다.

사용자가 ER-C3G 요청에서 제시한 진술: “실제 macOS Safari에서 일반 검사부터 증거 해제까지 전체 핵심 흐름이 PASS였어.” 이 진술은 요청에 제시된 사용자 보고로 기록한다. 별도 실행 SHA나 서버 내부 메모리 상태까지 검증하는 증거는 아니다.

## 핵심 수용 항목

각 PASS의 출처는 `USER_ATTESTED`다.

| ID | 수용 범위 | 상태 | 출처 |
| --- | --- | --- | --- |
| C-01 | 일반 검사 핵심 흐름 | PASS | USER_ATTESTED |
| C-02 | 조사 모드 선택 및 검사 | PASS | USER_ATTESTED |
| C-03 | 비교 기준 저장 | PASS | USER_ATTESTED |
| C-04 | 재검사 | PASS | USER_ATTESTED |
| C-05 | 소멸 근거 평가 실행 | PASS | USER_ATTESTED |
| C-06 | 조사 증거 해제 조작 | PASS | USER_ATTESTED |

대화에 제공된 화면은 세 관찰 범주의 각 1건, 평가의 판단 보류와 해제 **요청** 안내를 보여준다. 캡처 판독과 사용자 수용 진술은 구별한다. 해제 버튼 조작이나 요청 안내는 서버 메모리의 즉각적·완전한 삭제를 증명하지 않는다.

## 기존 F-01~F-10 매핑

복합 항목은 일부 확인만으로 전체 PASS로 바꾸지 않는다.

| QA ID | 확인된 범위 | 미확인 범위 | 전체 상태 |
| --- | --- | --- | --- |
| F-01 | 일반 검사 핵심 흐름 수용 | 모든 검토·메모·내보내기 세부 기능 | NOT_TESTED |
| F-02 | 조사 모드 선택과 첫 검사 수용 | 추가 세부 조건은 별도 평가 없음 | PASS |
| F-03 | 기준 저장과 재검사 수용; 제공된 화면에 세 범주 각 1건 표시 | 실행 SHA의 독립 증빙 | PASS |
| F-04 | 평가 실행 수용; 화면에서 판단 보류와 분석 한계 표시 확인 | 모든 기술 문구의 사용자 이해도 | NOT_TESTED |
| F-05 | 해제 조작 수용 및 해제 요청 안내 화면 | 서버 내부의 즉시 완전 삭제 | NOT_TESTED |
| F-06 | 없음 | INCOMPARABLE 및 TTL 만료 안내 | NOT_TESTED |
| F-07 | 없음 | 정상 0 Finding 수동 확인 | NOT_TESTED |
| F-08 | 없음 | 실제 200% 확대, 키보드 전용, 좁은 창 | NOT_TESTED |
| F-09 | 없음 | VoiceOver 및 iOS Safari | NOT_TESTED |
| F-10 | 없음 | 정식 문구 이해도·발견 가능성 평가 | NOT_TESTED |

F-03의 PASS는 해당 표의 기준 저장과 A/B → A/C 재검사 흐름에 한정되며, 실행 SHA 증빙은 별도 한계로 남는다. 자동화의 성공은 수동 미확인 항목의 PASS로 사용하지 않는다.

토큰, Handle, 내부 경로, Manifest 원문과 실제 사용자 소스는 이 기록에 포함하지 않는다. 수용 결정과 한계는 [ER-C3G 결정 문서](er-c3g-safari-core-user-acceptance-final.md)를 참조한다.
