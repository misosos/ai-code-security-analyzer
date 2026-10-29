# Phase 5A — 로컬 FastAPI 백엔드

이 API는 React UI가 기존 정적 분석 엔진의 검증된 구조화 결과를 사용할 수 있도록 하는 로컬 전용 인터페이스다. 취약점 확정 서비스나 OS 파일시스템 샌드박스가 아니다. 사람 대상 사용성 평가는 계속 `NOT_TESTED`다.

## 실행

Python 3.12와 잠금된 uv 환경을 사용한다. 서버는 `127.0.0.1:8765`에만 바인딩되고 Uvicorn access log를 끈다. 환경 변수에 target과 43자 이상의 URL-safe 토큰을 지정해야 한다. 길이와 문자 집합 검사는 난수성을 증명하지 않으므로 비밀관리 도구나 암호학적으로 안전한 생성기로 토큰을 만든다.

```sh
AI_CODE_SECURITY_TARGET=/absolute/path/to/project \
AI_CODE_SECURITY_API_TOKEN='<at-least-43-url-safe-random-characters>' \
uv run python -m ai_code_security_analyzer.api
```

규칙 디렉터리를 바꾸려면 `AI_CODE_SECURITY_RULES_DIR`에 신뢰할 로컬 규칙 디렉터리를 지정한다. 기본값은 저장소의 `rules/`다. 브라우저 Origin은 기본적으로 모두 거부한다. 로컬 UI Origin을 사용할 때는 `AI_CODE_SECURITY_ALLOWED_ORIGINS`에 정확한 `http://localhost:<port>` 또는 `http://127.0.0.1:<port>` origin을 쉼표로 구분해 지정한다. 지정된 Origin에만 GET/POST와 `Content-Type`, `X-Local-API-Token` 헤더를 허용하며 credentials는 허용하지 않는다. 와일드카드 Origin은 지원하지 않는다.

## API

모든 경로는 `/api/v1` 아래에 있다.

| Method | Path | 동작 |
| --- | --- | --- |
| GET | `/health` | 서비스 프로세스 응답 상태. Semgrep 설치·동작을 보증하지 않는다. |
| GET | `/options` | 고정 target ID와 허용된 규칙 profile ID/label을 제공한다. 실제 경로는 반환하지 않는다. |
| POST | `/scans` | 등록된 target과 profile 하나로 동기 scan을 실행한다. |

요청 예시:

```http
POST /api/v1/scans
Content-Type: application/json
X-Local-API-Token: <local-secret>

{"target_id":"local-project","rule_profile_id":"baseline"}
```

`target_id`는 `local-project`만 허용한다. profile은 `baseline`, `eval-experimental`, `command-injection-experimental` 중 하나다. Experimental profile은 요청에서 명시적으로 선택해야 한다. 요청에 파일 경로나 규칙 파일명을 전달할 수 없고 알 수 없는 필드는 거부한다.

## 보호 경계

- scan 요청에는 `X-Local-API-Token` 인증이 필요하다. 토큰을 URL, cookie 또는 로그에 넣지 않는다.
- Host는 기본적으로 `localhost`와 `127.0.0.1`만 허용하고, Origin은 기본적으로 존재할 수 없다. Origin이 있으면 설정된 정확한 loopback origin이어야 한다. 허용 목록이 설정되면 동일한 목록만 CORS에 사용한다.
- Content-Type은 JSON으로 제한하고 요청 본문은 16 KiB 이하로 제한한다.
- 동시 scan은 프로세스당 하나다. 두 번째 요청은 `scan_already_running`으로 거부된다. Semgrep의 기존 60초 timeout과 2 MB 출력 제한을 그대로 쓴다.
- target과 rules 디렉터리는 설정 시 실제 경로로 정규화하고 서로 겹치지 않아야 한다. scan 직전에 target과 규칙 경로를 다시 확인하고 target 아래의 symlink를 거부한다. 사전 검사 시간은 5초, 방문 항목은 100,000개로 제한한다.
- 이 검사는 경로 변경과 symlink 위험을 줄이지만 TOCTOU 경쟁을 완전히 제거하지 않는다. 프로세스 수준 CPU·메모리·파일 접근·네트워크 격리도 제공하지 않는다. 신뢰할 수 없는 프로젝트는 OS/container 격리에서 검사한다.
- loopback bind, Host/Origin 검사만으로 모든 DNS rebinding이나 로컬 웹 공격을 막는다고 보장하지 않는다. 실제 네트워크 차단은 OS 수준 정책이 필요하다.
- API는 브라우저 파일 업로드, 폴더 열람, 임의 경로 접근, 기록 저장, 외부 전송을 제공하지 않는다. CORS는 설정된 정확한 loopback Origin에 대해서만 제한적으로 동작한다. Phase 5B에서 빌드된 UI가 있으면 FastAPI가 이를 같은 출처로 제공하며, 개발 시 Vite는 loopback의 `/api`만 백엔드로 프록시한다.

## 결과 계약

응답 DTO는 공개 `Finding` 모델을 직접 직렬화하지 않는다. `scan_status`, `completed`, Semgrep 버전, 총 Finding/표시/생략 수, severity 집계, 고정 issue/limitation 코드, 최대 50개 Finding을 반환한다. JSON 응답은 1 MiB 이하이며 초과 시 고정 `response_limit_exceeded` 오류를 반환한다.

각 Finding에는 안전한 상대 경로와 줄, rule ID, severity, `unverified` 상태, `taint`/`pattern`/`unclassified` 분류, evidence validation 상태, 지원 ClaimType과 제한된 ClaimType·decision·reason code가 포함된다. 코드 원문, snippet, 자유 형식 Semgrep 메시지, stderr, 절대 경로, raw JSON/SARIF, token 및 traceback은 응답에서 제외한다. 상대 경로와 규칙 ID는 저장소 구조를 드러낼 수 있으므로 응답을 외부 공유에 안전한 익명 자료라고 간주하지 않는다.

한 번의 요청은 기존 `SemgrepAdapter._scan_with_evidence()`를 호출해 한 번의 Semgrep 실행/파싱 결과에서 Finding과 TaintEvidence를 얻는다. 각 Finding은 기존 Gate → EvidenceSummary → `consume_evidence_summary()`를 통과해야 supported claim을 받을 수 있다. Consumer 재검증이 실패하면 해당 Finding의 supported claim은 빈 목록으로 반환되고 고정 검증 실패 코드가 붙는다.

`completed`는 Semgrep scan 상태만 나타내며 안전성을 의미하지 않는다. 내부 scan 실패도 HTTP 요청 처리는 정상적으로 마무리될 수 있으므로, HTTP 상태와 `scan_status`는 구별한다. partial/failed 상태는 `completed=false`이며, failed 상태에서는 근거 claim을 제공하지 않는다. 50건 이후 Finding은 생략 수를 명시하며 생략된 Finding의 개별 근거는 검증 결과에 포함되지 않는다. Finding 0건도 코드 안전성을 뜻하지 않는다.

Taint 규칙 매치는 Source→Sink 전체 경로, 실제 Source 위치, Sink 인자 위치, Sanitizer 효과 또는 취약점 확인을 뜻하지 않는다. experimental Command Injection profile은 현재 신뢰 규칙 등록을 사용하는 기존 Gate/Consumer 경로에서만 구조적으로 분류된다. severity는 검증 상태와 별개의 값이다.

## 엔드포인트 오류 코드

요청 오류는 `invalid_request`, `unauthorized`, `host_not_allowed`, `origin_not_allowed`, `target_not_allowed`, `rule_profile_not_allowed`, `scan_already_running`, `response_limit_exceeded`, `internal_error`처럼 고정된 코드만 반환한다. 상세 예외, 경로, Semgrep stderr는 반환하지 않는다.

## 검증

API 단위 테스트는 fake adapter를 사용하고, 필수 Semgrep E2E는 Semgrep OSS 1.182.1에서 합성 프로젝트를 검사한다. baseline pattern, eval taint, Command Injection taint profile을 각각 확인한다. 기존 CLI와 JSON schema 1.0은 별도 회귀 테스트로 보호한다. 기본 분석 경로는 LLM/Ollama 호출을 추가하지 않는다.

후속 React UI는 토큰을 URL이나 cookie로 보내지 않아야 하며, API 응답 문자열을 화면에 넣을 때 HTML escaping을 적용해야 한다. CORS와 허용 Origin은 프론트엔드 연결 Phase에서 별도로 검토한다.
