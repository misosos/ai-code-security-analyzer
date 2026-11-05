# ER-C3G Safari 핵심 조사 흐름 사용자 수용

## 목적과 기준

이 문서는 사용자가 보고한 macOS Safari 핵심 조사 흐름 수용을 기록한다. 제품 기능이나 보안 계약은 변경하지 않는다.

- 기록 기준 SHA: `a52b2ec660f33592aaaa7b40f524e357283ab4c4`
- 기준 CI Run: `42008218723`, push / completed / success
- Python tests and CLI, React dashboard, Semgrep 1.182.1 integration: 성공
- Artifact: 0개
- 수용 출처: `USER_REPORTED_MANUAL_SAFARI_ACCEPTANCE`
- 증거 유형: `DIRECT_USER_ATTESTATION`
- 실제 실행 SHA: `EXECUTED_SHA_NOT_INDEPENDENTLY_VERIFIED`

기준 SHA는 기록 시점의 검증된 main이다. 사용자가 수동 시험에서 실행한 코드의 정확한 SHA를 별도로 제출하지 않았으므로 둘이 같다고 확정하지 않는다. 보고일은 2026-11-05이며 실제 수행일과 macOS/Safari 상세 버전은 별도로 기록되지 않았다.

## 사용자 수용과 화면 증거

사용자는 ER-C3G 요청에서 “실제 macOS Safari에서 일반 검사부터 증거 해제까지 전체 핵심 흐름이 PASS였어”라고 제시했다. 수용 범위는 일반 검사, 조사 모드 선택 및 검사, 기준 저장, 재검사, 소멸 근거 평가 실행, 조사 증거 해제 조작이다. 사용자 조작의 보고를 기록한 것이며 Codex가 사용자의 브라우저를 직접 조작한 결과가 아니다.

사용자는 대화 중 Safari 화면 캡처도 제공했다. 캡처에는 비교 범주 각 1건, `현재 증거로 판단 불가`, 분석 한계, 해제 요청 후 비활성화된 조사 버튼과 안내가 표시된다. 해당 화면을 확인한 것과 사용자 진술을 별개로 취급한다. 캡처는 저장소에 복사하지 않았으며 별도 실행 로그는 제공되지 않았다.

자세한 QA ID와 출처는 [사용자 수용 기록](er-c3f-user-acceptance-record.md)에 있다. 해제 조작 수용은 서버 메모리의 즉각적·완전한 삭제를 보증하지 않는다.

## 자동화 검증과 관계

[ER-C3E 보안 검증](er-c3e-investigation-security-acceptance.md)은 합성 데이터로 Registry, 평가기, API 및 브라우저 흐름을 시험했다. [ER-C3F QA 환경](er-c3f-safari-investigation-manual-qa.md)은 단일 worker와 격리된 합성 프로젝트로 실제 FastAPI–Semgrep 흐름과 도구 정리를 검증했다. 그 문서의 과거 결과는 자동화 근거이며 이번 사용자 수동 수용과 독립적이다. 기존 문서에 남은 `NOT_TESTED`는 당시 기록이며 이 문서가 후속 수용 범위를 명시한다.

사용자 수동 검증 근거가 별도로 없는 200% 확대, 320/390px 수동 창, 키보드 전용 전체 흐름, VoiceOver, iOS Safari, 실제 TTL 만료, 서버 재시작 오류, INCOMPARABLE, 정상 0 Finding, 모든 메모·내보내기·백업 기능 및 정식 문구 이해도는 `NOT_TESTED`다. 장시간 메모리 안정성과 여러 사용자 동시 사용도 수용하지 않았다.

## 보안 의미와 운영 제한

Finding 미관찰은 취약점 해결의 증거가 아니다. 같은 Finding ID는 코드 내용 동일성을, `PATH_REPORTED_SCANNED`는 전체 검사 완전성을 증명하지 않는다. `EXPLANATION_SUPPORTED`는 코드 수정 확인이 아니며 `UNDETERMINED`는 수정 완료를 뜻하지 않는다. 사용자 수용은 전체 보안 승인이나 취약점 부재 증명이 아니다.

Registry는 프로세스 로컬이며 Run 최대 4개, Session 최대 2개, 절대 TTL 최대 15분이다. 공식 launcher의 단일 worker가 지원 범위다. 다중 worker 및 다중 사용자 격리, 영구 저장과 서버 재시작 후 복구는 지원하지 않는다. 하드 RSS 상한이 없고 브라우저 종료 시 Release 전달을 보장하지 않는다.

운영 승인: `DEPLOYMENT_APPROVAL_NOT_GRANTED`.

## 재검증과 결정

실제 Safari 200% 확대, 키보드 전용 사용, VoiceOver, iOS Safari, TTL 만료 UX, 장시간 안정성 및 실제 분석가 사용성은 각각 별도 근거가 필요하다. 수용 대상 코드나 보안 경계가 변경되면 해당 흐름을 다시 검증하고 실행 SHA를 기록한다.

핵심 사용자 수용: `ER_C3G_SAFARI_CORE_USER_ACCEPTED`.

이 수용은 모든 Safari 버전 호환성, 전체 접근성, 운영 배포, 다중 사용자·worker 또는 취약점 자동 해결을 승인하지 않는다. 문서 전용 변경이므로 기능 테스트는 `NOT_RUN_DOC_ONLY`다. 새 커밋의 원격 CI는 `PENDING_USER_PUSH`다.
