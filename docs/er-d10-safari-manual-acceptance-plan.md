# ER-D10 Safari 분석가 수동 검수 계획

## 범위와 준비 상태

목적은 실제 macOS Safari 사용자가 Finding 변화와 증거의 한계를 구분하고 후속 작업을 선택할 수 있는지 확인하는 것이다. 자동화는 환경의 재현 가능성을 확인한다. 사람의 조작·이해·수용은 [별도 결과 기록](er-d10-analyst-acceptance-results.md)에 사용자 응답을 받은 뒤 작성한다.

기준 SHA는 `6fc6ce98b914d3727296b539b4e27a4f3f186cd0`이다. 실제 검수 시에는 실행기가 사용자 터미널에 표시한 **검수 코드 SHA와 추적 파일 변경 여부**를 기록한다. 추적 파일 변경이 있으면 SHA만으로 실행 버전을 특정할 수 없으므로 해당 상태도 남긴다. Git SHA가 확인된 것과 사용자가 Safari에서 실행한 것은 별개의 증거다.

Mac Apple Silicon, Python 3.12.7, uv, Semgrep OSS 1.182.1, Node.js 24 및 실제 Safari가 필요하다. 테스트 대상은 전적으로 QA 소유 합성 JavaScript다. ER-D9의 EJS 원본을 사용한 검수라고 기록하지 않는다. 소스와 trusted baseline 규칙은 임시 사본으로 준비한다. 일반 제품의 Target·규칙·API 계약을 변경하지 않는다.

## 설치와 실행

프로젝트가 설치된 Mac의 새 터미널에서 실행한다. 기존 Desktop 또는 4173 서버 터미널은 그대로 둔다.

```bash
cd /tmp/ai-csa-er-d10-safari-acceptance
uv sync --locked --group dev
uv run --locked python --version
semgrep --version
cd frontend
mise exec node@24 -- npm ci
mise exec node@24 -- npm run build
mise exec node@24 -- npm run qa:investigation:safari
```

Python은 `3.12.7`, Semgrep은 `1.182.1`이어야 한다. 실행기는 Node 24와 이 버전들을 확인하고, loopback의 별도 동적 포트에 단일 Worker API와 Vite를 띄운다. 4173은 선택에서 제외한다. 임시 Token은 실제 대화형 터미널에서만 표시한다. 터미널을 파일로 리다이렉트하거나 세션을 녹화하지 않는다.

터미널에 표시된 접속 주소를 **Safari**로 연다. 같은 터미널의 Token을 페이지의 `로컬 API 토큰` 입력에만 붙여 넣는다. Token, Handle, 원시 출력, 내부 임시 경로를 채팅·기록·화면 캡처에 남기지 않는다. Safari > Safari에 관하여와 macOS 시스템 정보에서 실제 버전을 확인한다. 자동으로 Safari를 제어하지 않는다.

## 참가자용 절차: 1차 A/B → A/C

이 절차를 진행하는 동안 아래 평가자 기준을 먼저 읽고 답을 외우지 않는다. A05는 선택지나 정답을 미리 제공하지 않고 사용자의 자유 응답을 받는다. Map 자체가 제시한 후속 안내를 읽는 것은 허용한다.

1. 검사 대상 `Safari QA 합성 프로젝트 A`, 규칙 모음 `baseline`을 선택한다. `소멸 근거 조사 선택`을 열고 `소멸 근거 조사`를 선택한다. `규칙 파일 동일성 증거 포함`을 켠다.
2. 기준 검사를 실행한다. `stable.js`, `retired.js`의 Finding 두 건을 확인한 뒤 `현재 결과를 비교 기준으로 저장`을 누른다. 검사 버튼을 연속해서 누르지 않는다.
3. 실행기 터미널로 돌아가 Enter를 **한 번** 누른다. 변경 완료 안내가 나오면 Safari에서 `검사 시작`으로 이동해 재검사한다. 실험자는 합성 대상을 변경하지만 제품의 Source Snapshot은 수집되지 않는다.
4. `검사 결과`에서 `검사 결과 비교`를 열고 변화 범주를 읽는다. `소멸 근거 조사 실행`을 누른다. 규칙 파일 바이트 비교, Security Evidence Gap Map, Finding별 접힌 상세를 연다.
5. **A01:** Finding이 현재 검사에서 보이지 않는다는 사실로 무엇을 판단할 수 있는지 본인 말로 답한다.
6. **A03:** 표시된 규칙 바이트 결과가 적용되는 범위와 여전히 확인되지 않은 규칙 정보를 본인 말로 답한다.
7. **A04:** Map에서 확인된 변화, 소스 Snapshot, 전체 로딩 규칙, Scope 완전성, 해결 여부를 찾아 각각 어디에 표시됐는지 말한다. 경로 제외 항목은 2차에서 찾는다.
8. **A05:** 현재 관찰을 근거로 다음에 직접 수행할 작업 한 가지와 선택 이유를 본인 말로 기록한다. 이 문서의 평가자 기준을 먼저 읽지 않는다. 실제 Git Diff 조회나 재검사를 수행하지 않았다면 완료한 작업으로 쓰지 않는다.
9. **A07:** `조사 증거 해제`를 누른 뒤 Map이 사라지고 재조사에 새로운 검사 증거가 필요하다는 안내가 나오는지 확인한다. UI에서 관찰한 범위만 기록한다. 서버의 이전 Handle 재사용 거부는 별도 자동 검증 근거를 사용하며 사용자가 Handle을 추출·보관할 필요는 없다.
10. 실행기 터미널에서 Ctrl+C를 누른다. `qa_cleanup=complete`를 확인한다. 다음 시나리오는 새 실행·새 Token·새 주소에서 시작한다.

## 참가자용 절차: 2차 Skip / Partial

```bash
cd /tmp/ai-csa-er-d10-safari-acceptance/frontend
mise exec node@24 -- npm run qa:investigation:safari -- --scenario=skip
```

1. 새 Safari 주소에 접속해 새 Token을 입력한다. 1차와 같은 Target/Profile, 조사 모드, 규칙 바이트 옵션을 선택한다. 기준 두 Finding을 검사하고 저장한다.
2. 실행기 터미널에서 Enter를 한 번 누른다. QA 소유 대상의 `.semgrepignore`에 `retired.js`가 추가된다. 원본 trusted rule은 변경하지 않는다.
3. 재검사하면 `stable.js`만 관찰되고 검사는 부분 완료다. 일반 Comparison이 차단된 상태에서 별도 서버 조사를 실행한다. Map과 기준에만 관찰된 Finding의 상세를 읽는다.
4. **A02:** 해당 경로의 제외 관찰로 어디까지 말할 수 있는지 본인 말로 답한다.
5. **A06:** 현재 검사와 전체 평가 상태를 읽고 정상 완료 검사로 해석해도 되는지, 이유와 함께 답한다.
6. **A04 보완:** Finding별 경로 제외와 검사 전체 Scope 상태의 적용 범위를 구분해 찾는다. 규칙 바이트 결과가 1차와 어떻게 다른지 읽는다.
7. **A05 보완:** 현재 상황에서 다음 확인 작업 한 가지와 그 근거를 본인이 선택한다. 자유 응답을 먼저 보존한다.
8. 증거를 해제하고 Ctrl+C로 종료한다. 이 실행도 두 검사만 사용한다. Rate Limit을 해제하거나 TTL을 단축하지 않는다.

## 화면·접근성 추가 점검

각 항목을 실제로 확인한 경우에만 별도 상태를 기록한다. 1440×900, 1024px, 768px, 390px, 320px 창 크기를 각각 확인한다. Safari 200% 확대는 실제 Safari 확대 명령으로 수행하고 CSS 창 크기 변경과 구분한다. Tab/Shift+Tab/Enter/Space로 검사·기준 저장·접힌 상세·해제를 조작하면서 Focus, 비활성 버튼, 오류, Map의 위계와 가독성을 확인한다. 실제로 측정하지 않은 창 크기와 확대율은 확인했다고 쓰지 않는다.

만료 안내는 새 격리 실행의 실제 증거가 최대 TTL 15분을 경과한 경우에 확인한다. 기본 A01~A07 중간에 증거가 만료되면 새 실행으로 시나리오를 처음부터 수행한다. 자동화의 가짜 시계나 WebKit 결과는 실제 Safari 만료 확인이 아니다. VoiceOver와 iOS Safari는 별도 사용자 조작 없이는 `NOT_TESTED`다.

## 평가자용 기대 관찰과 판정

사용자 자유 응답을 먼저 기록하고 이 기준과 대조한다. 답을 유도해서 얻은 응답은 자발적 이해와 구분한다.

| ID | 기대 관찰·이해 | 수동 근거 |
| --- | --- | --- |
| A01 | Finding ID 변화만으로 취약점 해결을 입증하지 못한다고 설명 | 사용자의 원문 응답 |
| A02 | 특정 경로 제외와 전체 검사 완료를 구분 | 사용자의 원문 응답과 Finding 상세 위치 |
| A03 | 선택된 단일 파일 사본 바이트와 전체 Loaded Rule Inventory를 구분 | 사용자의 원문 응답 |
| A04 | 관찰·미수집·미검증을 찾고 Finding별/전체 범위를 구분 | 사용자가 실제로 찾은 영역 |
| A05 | 화면의 관찰에 연결된 후속 작업과 이유를 직접 선택 | 선택한 작업·이유를 답한 그대로 보존 |
| A06 | `PARTIAL`/`INCOMPARABLE`을 정상 완료로 해석하지 않음 | 사용자의 원문 응답 |
| A07 | 해제 후 이전 Map이 유효한 결과로 남지 않음을 직접 확인 | UI 조작과 관찰; 서버 404는 별도 자동 근거 |

1차는 shared/baselineOnly/currentOnly 각 1건, 전체 `UNDETERMINED`, 동일 선택 바이트가 예상된다. 2차는 shared 1건, baselineOnly 1건, currentOnly 0건, `PATH_EXPLICITLY_SKIPPED`/`SUPPORTED`, 현재 `PARTIAL`, aggregate `INCOMPARABLE`, Rule Bytes `UNVERIFIED`가 예상된다. 공개 DTO가 구체적인 Skip reason을 제공하지 않으므로 화면이 `.semgrepignore` 사유를 직접 수집했다고 답을 유도하지 않는다. 어느 흐름도 수정 완료·안전·전체 규칙 적용을 증명하지 않는다.

## 종료·실패·제한

Ctrl+C 또는 SIGTERM은 이 실행기가 소유한 프로세스 그룹과 임시 폴더만 정리한다. 토큰을 삭제하거나 브라우저를 닫는 것만으로 서버 종료와 Release가 보장되는 것은 아니다. `qa_cleanup_failed`나 연결 실패가 발생하면 고정 오류 코드와 실행 단계를 기록하고 해당 항목을 PASS로 바꾸지 않는다. 다른 서버에 종료 명령을 내리지 않는다.

Run 최대 4개, Session 최대 2개, 절대 TTL 900초, 단일 Worker, Process-local 증거, 영구 저장·재시작 복구 없음과 기존 Rate Limit은 유지된다. 규칙 주석 변경은 이번 수동 실행기에서 지원하지 않으며 ER-D9/D8의 별도 자동화 근거다. API 오류 강제 주입·실제 iOS·VoiceOver는 기본 검수에 포함되지 않는다. P0/P1 발견 시 완료 판정을 보류하고 안전한 재현 단계와 영향을 기록한다.
