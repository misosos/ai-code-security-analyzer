# ER-C3E 사용자 수용 점검표

이 문서는 실제 사용자가 일반 검사와 **소멸 근거 조사** 흐름을 확인하기 위한 수동 QA 절차다. 자동 테스트 결과와 별개이며, 각 항목의 기본 상태는 `NOT_TESTED`다. Finding 미관찰은 취약점 수정이나 해결 완료의 증거가 아니다.

## 1. 격리된 합성 프로젝트 준비

실제 사용자 프로젝트를 변경하지 않는다. 아래 예시는 임시 디렉터리 안에서만 사용한다.

```bash
mkdir -p /tmp/ai-csa-er-c3e-manual
cat > /tmp/ai-csa-er-c3e-manual/stable.js <<'EOF'
const stableInput = "2 + 2";
eval(stableInput);
EOF
cat > /tmp/ai-csa-er-c3e-manual/retired.js <<'EOF'
const retiredInput = "3 + 3";
eval(retiredInput);
EOF
```

등록 대상 설정은 저장소의 기존 로컬 대상 등록 절차를 사용한다. 토큰 값, 사용자 경로 또는 소스 원문을 점검 기록에 복사하지 않는다.

## 2. 공식 로컬 API 실행

Python 3.12.7, Semgrep 1.182.1과 잠긴 의존성을 사용한다. 공식 launcher는 loopback, 단일 worker, reload 비활성 조건으로 조사 API를 활성화한다.

```bash
export AI_CODE_SECURITY_TARGET='/tmp/ai-csa-er-c3e-manual'
export AI_CODE_SECURITY_API_TOKEN='<별도로 생성한 로컬 토큰>'
export AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:4173'
uv run --locked python -m ai_code_security_analyzer.api
```

복수 대상은 `AI_CODE_SECURITY_TARGET` 대신 `AI_CODE_SECURITY_TARGETS`를 사용한다. 규칙 경로는 필요할 때 `AI_CODE_SECURITY_RULES_DIR`로 설정한다. Vite 프록시의 `AI_CSA_API_PROXY_TARGET`은 서버 설정과 별개다. 토큰을 셸 기록, 캡처, 문서에 남기지 않는다. 다른 Safari QA 서버를 종료하거나 재사용하지 않는다.

별도 터미널에서 대시보드를 고유 포트로 실행한다.

```bash
cd frontend
npm ci
AI_CSA_API_PROXY_TARGET=http://127.0.0.1:8765 npm run dev -- --host 127.0.0.1 --port 4173 --strictPort
```

브라우저에서 `http://127.0.0.1:4173`에 접속한다.

## 3. 수동 점검

| ID | 절차 | 기대 결과 | 상태 |
| --- | --- | --- | --- |
| UA-01 | 기본 화면에서 검사 방식을 확인한다. | `일반 검사`가 기본이며 조사 API가 자동 실행되지 않는다. | NOT_TESTED |
| UA-02 | 로컬 토큰과 합성 대상을 선택해 일반 검사를 실행한다. | 기존 Finding 화면, 검토 상태, 메모, 내보내기가 정상 동작한다. | NOT_TESTED |
| UA-03 | 일반 검사 결과를 비교 기준으로 저장하고 재검사한다. | 기존 브라우저 비교가 동작하며 서버 조사 증거가 있다고 표시하지 않는다. | NOT_TESTED |
| UA-04 | 검사 설정에서 `소멸 근거 조사`를 선택한다. | 최대 15분 임시 보관과 해결 판정 제한을 읽을 수 있다. | NOT_TESTED |
| UA-05 | 합성 프로젝트의 첫 조사 검사를 실행한다. | `stable.js`와 `retired.js` Finding 및 서버 증거 연결 안내가 표시된다. | NOT_TESTED |
| UA-06 | 첫 조사 결과를 비교 기준으로 저장한다. | 같은 실행에서 발급된 증거가 기준에 연결됐다는 안내가 표시된다. | NOT_TESTED |
| UA-07 | `retired.js`의 eval을 제거하고 `added.js`에 새 eval 패턴을 만든다. | 변경은 `/tmp/ai-csa-er-c3e-manual` 안에서만 일어난다. | NOT_TESTED |
| UA-08 | 같은 대상과 규칙으로 두 번째 조사 검사를 실행한다. | 현재 결과와 새 Run 증거가 함께 연결된다. | NOT_TESTED |
| UA-09 | 검사 결과 비교에서 `소멸 근거 조사 실행`을 누른다. | shared A, baselineOnly B, currentOnly C가 Finding ID 관찰 범주로 표시된다. | NOT_TESTED |
| UA-10 | baselineOnly 상세와 분석 한계를 읽는다. | 코드 스냅샷 미수집, 규칙 동일성 제한, 경로 증거 의미가 표시된다. | NOT_TESTED |
| UA-11 | 결과 문구를 확인한다. | 수정 완료, 취약점 제거, 안전성 검증 완료로 표현하지 않는다. | NOT_TESTED |
| UA-12 | `조사 증거 해제`를 누른다. | 해제 요청 안내가 표시되며 기존 화면 Finding은 유지된다. | NOT_TESTED |
| UA-13 | 해제 후 다시 평가를 시도한다. | 새 조사 검사가 필요하다는 안내가 나오고 이전 결과를 복구하지 않는다. | NOT_TESTED |
| UA-14 | 서버를 재시작하거나 짧은 TTL의 격리 시험 서버에서 만료를 재현한다. | `증거가 만료되었거나 사용할 수 없음` 안내가 나오며 빈 정상 결과로 바뀌지 않는다. | NOT_TESTED |
| UA-15 | 토큰을 지우고 조사 상태를 확인한다. | Handle 해제를 시도하고 토큰이나 Handle을 화면 오류에 노출하지 않는다. | NOT_TESTED |

운영 TTL 900초를 수동 시험을 위해 변경하지 않는다. 만료 시험은 테스트 전용 app/clock 설정에서만 수행한다.

## 4. Safari, 모바일 및 확대

다음은 자동화 결과로 대체하지 않는다.

| ID | 절차 | 기대 결과 | 상태 |
| --- | --- | --- | --- |
| UA-S01 | 실제 macOS Safari에서 UA-01~UA-13을 수행한다. | 버튼, disclosure, 비교 패널과 해제가 정상 동작한다. | NOT_TESTED |
| UA-S02 | Safari에서 200% 확대한다. | 텍스트나 조작 요소가 잘리지 않고 가로 페이지 넘침이 없다. | NOT_TESTED |
| UA-S03 | 390px 및 320px 상당 창 너비를 확인한다. | 조사 결과와 긴 상태 문구가 줄바꿈되며 읽을 수 있다. | NOT_TESTED |
| UA-S04 | 키보드만으로 모드 선택, 검사, 기준 저장, 평가, 해제를 수행한다. | 포커스가 보이고 순서가 자연스럽다. | NOT_TESTED |
| UA-S05 | VoiceOver로 제목, 상태, 오류를 확인한다. | 상태 변화와 오류가 의미 있는 이름으로 전달된다. | NOT_TESTED |

iOS Safari와 VoiceOver는 별도 장비·사용자 검증이 필요하다.

## 5. PASS/FAIL 기록

각 상태를 `PASS`, `FAIL`, `BLOCKED` 중 하나로 바꾸고 다음 정보만 기록한다.

- 날짜와 브라우저 버전
- 실행한 커밋 SHA
- 항목 ID
- 기대 결과와 실제 결과의 차이
- 재현에 필요한 합성 파일 이름과 조작 단계
- 민감정보를 제거한 화면 캡처

토큰, opaque Handle, 내부 scan reference, 절대 경로, 원본 Manifest, 실제 사용자 소스는 기록하지 않는다. FAIL은 기능 결함과 문구·접근성 문제를 구분해 작성한다.
