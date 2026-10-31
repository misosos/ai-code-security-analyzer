# Phase UI-D4B — UI 콘텐츠 간소화 및 기능 필요성 검토

## 판정 범위

- 기준 HEAD: `6c8c5af29821505928f108190d07159f2683238d`
- 시작 시 origin/main 및 GitHub main: 기준 HEAD와 일치
- 시작 시 확인한 Actions: Run `41191186176`, `push / completed / success`
- 이번 검수: 합성 API 응답을 이용한 Chromium 브라우저 테스트
- 사용한 설계 지침: `design-taste-frontend`의 App Screen 정보 계층 및 점진적 정보 공개
- 브라우저 검증: Playwright Chromium. 실제 Safari와 axe 자동 검사는 이번에 실행하지 않음

Run 41191186176은 시작 SHA의 CI 근거다. 이번 Phase 커밋이 만들어지면 그 새 SHA의 원격 CI 성공 근거로 취급하지 않는다.

## 감사 분류

| 항목 | 판정 | 변경 및 이유 |
|---|---|---|
| 프로젝트·규칙·토큰 선택, 검사 실행 | KEEP | 핵심 사용 경로이므로 유지 |
| API 연결 실패 및 재시도 | KEEP | 실제 연결 상태와 복구 동작 유지 |
| Finding 검색·필터·선택 | KEEP | 기존 동작 유지 |
| 결과 내보내기·초기화 | KEEP | API 응답 범위와 메모리 초기화 의미 유지 |
| 검사 결과는 취약점 확정이 아니라는 경고 | KEEP | 검사 시작과 Finding 상세의 관련 위치에 유지 |
| 0건은 안전 증명이 아니라는 안내 | KEEP | 0건 결과 화면에 남김 |
| 세션 간 결과 복구 불가 | SIMPLIFY | 결과 페이지 제목 아래 한 번, 사용 안내에서 한 번 설명 |
| 프로젝트 선택 안내 | SIMPLIFY | “등록된 프로젝트만 검사할 수 있습니다.” |
| 규칙 선택의 일반 설명 | REMOVE_CANDIDATE | 입력 레이블 자체로 역할을 알 수 있어 기본 설명 제거. 실험 규칙 경고는 해당 선택 시에만 유지 |
| 토큰 설명 및 보관 정책 | SIMPLIFY / COLLAPSE | 기본 문구는 “서버에서 발급한 토큰을 입력하세요.”, 메모리 보관·헤더 전송·새로고침 시 삭제 설명은 접힌 영역에 유지 |
| 시작 화면의 3단계 안내 | REMOVE_CANDIDATE | 화면에서 중복되는 단계 카드를 제거. 스크린리더용 순서 목록은 유지 |
| 시작 화면의 결과 검토 경고 | KEEP / SIMPLIFY | “탐지 결과는 검토 후보입니다.”와 파일 위치·근거 확인 문장만 유지 |
| 상단 API 상태, 사이드바 상태, 옵션 준비 상태 | SIMPLIFY | 상단 API 상태만 기본 표시. 사이드바 중복 상태와 설정의 “옵션 불러옴” 제거 |
| 빈 결과 문구 | SIMPLIFY | 짧은 제목·설명·“검사 시작” 버튼. 세션 제한은 결과 페이지 제목 아래에 유지 |
| 서버 운영 명령, 환경 변수, 허용 Origin, Vite 개발 | COLLAPSE | “서버 관리자 설정” 안에서 접근 가능하게 유지 |
| 핵심 보안 용어 | KEEP / SIMPLIFY | 검토 후보·심각도·미검증·근거 연결·규칙 모음만 기본 표시 |
| Taint/Source/Sink/Trace/Sanitizer | COLLAPSE | “전문 분석 용어 보기” 아래에 유지 |
| 정상 완료의 일반 제한 코드 | COLLAPSE / REMOVE_CANDIDATE | 일반적으로 반복되는 안전성 제한은 접힌 “검사 문제와 다음 조치”에서 생략. 0건, 요약 지표, Finding 상세에서 의미에 맞게 안내 |
| 부분 완료·오류·생략 결과 및 검증 실패 | KEEP | 실제 조치가 필요한 상태와 제한 정보는 표시하고 상세 코드도 접어서 접근 가능 |
| 전역 하단 안전성 안내 | REMOVE_CANDIDATE | 화면마다 반복하던 공통 문구 제거. 상태에 따라 결과·0건·부분 검사·Finding 상세에 배치 |

## 실제 기능 제거 검토

이번 Phase에서 제품 기능은 제거하지 않았다. 검사, 인증, 프로젝트·규칙 선택, 토큰 지우기, 검색, 필터, Finding 선택, 내보내기, 결과 초기화, API 재연결 및 Evidence 상세는 계속 사용할 수 있다.

검사 흐름 문구·중복 상태·전역 반복 문구는 UI 콘텐츠 정리 대상이었다. 시각적 3단계 안내는 제거했지만 접근성 순서 정보를 스크린리더 전용 목록으로 남겼다. 기능 삭제 후보 중 사용자 승인 없이 제거한 항목은 없다.

## 변경 전후

### 검사 시작

- Before: API 연결 상태 외에 사이드바의 옵션 준비 상태와 설정 패널의 옵션 상태가 반복됨.
- After: API 연결 상태를 상단에 한 번 표시. 오류·재시도는 필요한 때만 경고 영역에 표시.
- Before: 검사 설정 하단에 단계 안내와 유사한 취약점/안전성 제한이 함께 노출됨.
- After: 중복 단계 카드 대신 짧은 검토 후보 안내만 표시. 접근성 순서 목록은 시각적으로 숨겨 보존.
- Before: 프로젝트·규칙·토큰 아래에 기술 설명이 반복됨.
- After: 프로젝트 안내와 토큰 입력 지시만 짧게 표시. 토큰 저장·전송 세부사항은 접힌 영역에 둠.

### 결과 없음 / 0건

- 결과 없음은 “아직 검사 결과가 없습니다.”, 실행 안내, “검사 시작”으로 간결화.
- 현재 브라우저 세션의 결과만 표시한다는 제한은 결과 화면에서 한 번 명시.
- 정상 완료·0건은 “발견 항목이 없습니다”와 “검사되지 않은 문제까지 안전하다는 뜻은 아닙니다”를 유지.
- 완료 상태와 0건은 별도 상태로 렌더링되며, 0건을 안전 확인으로 표현하지 않음.

### 발견 항목 결과

- 기본 완료 화면에서 모든 일반 제한 코드를 “검사 문제” 목록으로 보여주던 중복을 제거.
- 실제 `issues`와 의미 있는 제한 코드는 접힌 조치 목록으로 유지.
- 검사 상태, 총 후보 수, 표시 수, 생략 수, 심각도 분포, 결과 내보내기 안내는 별도로 유지해 개념을 혼합하지 않음.
- 생략 수가 있을 때만 최대 50건 제한을 눈에 띄게 표시.
- Finding 상세의 간단한 제한 설명은 유지하고, 기술 상세의 같은 취지 각주를 제거.

### 사용 안내

- 기본 안내는 검사 절차 3단계와 등록 프로젝트 제한으로 정리.
- 서버 설치·실행, 환경 변수, 절대 경로, 무작위 토큰 생성, 허용 Origin, 기존 단일 프로젝트 설정, Vite 개발 방법은 접힌 “서버 관리자 설정”으로 이동.
- 핵심 용어 5개는 기본으로, 전문 데이터 흐름 용어는 접힌 설명으로 분리.
- 검사 범위의 세션 제한과 0건 비보증은 안내 페이지에서 계속 확인 가능.

## 보안·개인정보 검증

- 토큰은 `type=password` 입력에 남고, 저장 방식은 변경하지 않았다. Vitest와 Chromium 테스트에서 localStorage/sessionStorage에 값이 기록되지 않는 것을 확인했다.
- 실제 토큰·사용자 프로젝트·원격 코드는 사용하지 않았다. 캡처는 합성 프로젝트와 합성 API 응답을 이용했다. 토큰 입력 화면은 합성 전용 값이 마스킹된 상태다.
- FastAPI, CLI, Semgrep 어댑터, Finding/Evidence 타입·검증 의미, 다운로드 형식은 변경하지 않았다.
- 검토 후보 수와 표시 수, 생략 수를 별도로 유지했다. `omitted_finding_count > 0`일 때만 목록 제한을 표시하고, 내보내기는 현재 응답 범위임을 알린다.
- 0건·부분 검사·요청 오류·근거 검증 불가의 표현을 유지했다. 정상 완료가 안전성 보장이라는 표현은 추가하지 않았다.
- GitHub Intake 차단 상태 및 Docker Worker 검증 상태는 변경하지 않았다.

## 스크린샷

모든 화면은 Playwright Chromium의 합성 데이터다. 실제 검사 결과나 실제 API 연결 증거가 아니다.

| 상태 | 전 | 후 |
|---|---|---|
| 검사 시작 1440×900 | [Before](assets/ui-d4b/before/start-1440x900.png) | [After](assets/ui-d4b/after/start-1440x900.png) |
| 결과 없음 1440×900 | [Before](assets/ui-d4b/before/empty-results-1440x900.png) | [After](assets/ui-d4b/after/empty-results-1440x900.png) |
| Finding 결과 1440×900 | [Before](assets/ui-d4b/before/results-1440x900.png) | [After](assets/ui-d4b/after/finding-results-1440x900.png) |
| Finding 상세 | [Before](assets/ui-d4b/before/finding-detail-1440x900.png) | [After](assets/ui-d4b/after/finding-detail-1440x900.png) |
| 사용 안내 | [Before](assets/ui-d4b/before/guide-1440x900.png) | [After 기본](assets/ui-d4b/after/guide-basic-1440x900.png), [관리자 설정 펼침](assets/ui-d4b/after/guide-admin-expanded-1440x900.png) |
| 모바일 검사 시작 | — | [390×844](assets/ui-d4b/after/mobile-start-390x844.png) |
| 모바일 결과 | — | [390×844](assets/ui-d4b/after/finding-results-390x844.png) |
| 부분 검사 / API 오류 | — | [부분 검사](assets/ui-d4b/after/partial-results-1440x900.png), [API 오류](assets/ui-d4b/after/api-error-1440x900.png) |

시각 확인 결과: 기존 큰 한국어 타이포그래피, 왼쪽 사이드바, B 기반 보안 작업 공간을 유지했다. 정상 완료 화면에서 문제처럼 보이던 일반 제한 요약이 사라졌고, 0건 및 부분 검사의 주의 문구는 각각 해당 상태에서 확인된다. 사용 안내의 관리 명령은 기본 화면에서 접혀 있지만 실제로 펼쳐 접근할 수 있다.

## 테스트 및 정적 검사

- `npm run typecheck`: 통과
- `npm run build`: 통과
- `npm test -- --reporter=dot`: 4개 파일, 44개 테스트 통과
- `npm run test:browser`: Playwright Chromium 16개 테스트 통과
- `SEMGREP_REQUIRED=1 npm run test:e2e:real`: 합성 FastAPI–Semgrep E2E 1개 통과 (Semgrep 1.182.1)
- `git diff --check`: 통과
- 키보드 탐색, 모바일 메뉴, 입력·결과 흐름: 기존 브라우저 테스트 및 D4B 시나리오에서 통과
- axe 자동 검사 및 실제 Safari 검수: 이번 Phase에서 실행하지 않음

자동화 검증은 사용자 최종 수용을 뜻하지 않는다.
