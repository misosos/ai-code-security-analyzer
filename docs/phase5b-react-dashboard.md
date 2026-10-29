# Phase 5B — React Security Dashboard

## 기능

대시보드는 기존 FastAPI API의 `/api/v1/health`, `/api/v1/options`, `/api/v1/scans`만 사용한다. target ID와 rule profile ID만 전송하며 경로나 파일 업로드를 받지 않는다. 서버가 반환한 Finding DTO와 Gate → Summary → Consumer 결과를 그대로 검토용으로 보여준다.

Finding 목록은 최대 50건이며 심각도·유형·검증 상태 필터는 현재 API 응답에 표시된 결과에만 적용된다. 전체 수, 표시 수, 생략 수는 별도로 표시한다. `validated`는 근거의 구조적 연결이 확인됐다는 뜻이고 Finding은 `unverified` 상태로 유지된다. Severity는 도구 분류다. Source/Sink 위치와 trace가 unavailable/absent라면 그 상태를 그대로 보여준다.

검사 요청은 동기식이며 진행률이나 취소를 제공하지 않는다. API HTTP 오류와 HTTP 200의 Semgrep 실패 상태를 구분한다. 자동 재시도는 하지 않는다. Finding이 0건이어도 코드 안전성이 증명된 것은 아니다.

## 개발 서버

Node.js 24.22.2를 사용한다(`.nvmrc`). 프론트엔드는 `frontend/`에서 실행한다.

```sh
cd frontend
npm ci
npm run dev
```

API는 별도 터미널에서 실행한다. 토큰을 만들 때는 충분히 무작위인 URL-safe 값(43자 이상)을 사용하고 명령 기록이나 공유 문서에 실제 값을 남기지 않는다.

```sh
AI_CODE_SECURITY_TARGET=/absolute/path/to/approved/project \
AI_CODE_SECURITY_API_TOKEN='<random-url-safe-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:5173' \
uv run python -m ai_code_security_analyzer.api
```

Vite는 `127.0.0.1:5173`에만 바인딩하고 `/api`만 `127.0.0.1:8765`로 프록시한다. 프록시는 인증 토큰을 추가하지 않는다. 개발 서버에서는 브라우저의 `Origin: http://127.0.0.1:5173`을 API의 정확한 allowlist에 넣어야 한다. 와일드카드 Origin은 허용하지 않는다. Vite proxy는 개발 편의용 전달 경로이며 별도 접근통제나 OS 샌드박스가 아니다.

## 빌드 및 같은 출처 제공

```sh
cd frontend
npm ci
npm run typecheck
npm test
npm run build
```

빌드 산출물 `frontend/dist`가 있으면 FastAPI가 같은 출처에서 이를 정적으로 제공한다. 산출물이 없으면 정적 UI 경로를 mount하지 않아 API만 계속 실행할 수 있다. 같은 출처 UI에서 scan 요청의 Origin을 사용하는 환경은 해당 정확한 주소(예: `http://127.0.0.1:8765`)를 `AI_CODE_SECURITY_ALLOWED_ORIGINS`에 등록한다. 서버는 `/api` 경로를 먼저 처리한다. 정적 응답에는 `no-store`, `nosniff`, `no-referrer`, 제한된 CSP를 적용한다.

## 토큰 및 브라우저 보안

토큰은 password 입력과 React 메모리 상태로만 보관하며 요청의 `X-Local-API-Token` 헤더로 전달한다. URL·요청 본문·쿠키·localStorage·sessionStorage·IndexedDB·환경변수·정적 번들에 넣지 않는다. 지우기 버튼으로 메모리 값을 비울 수 있고 새로고침 시 값이 사라진다. 메모리 보관은 XSS에 대한 절대적 보호를 뜻하지 않는다.

서버 응답은 고정된 Pydantic DTO로 검증하고, 프론트엔드도 알 수 없는 상태와 필드를 거부한다. API 문자열은 React text node로 렌더링한다. 동적 HTML, 외부 링크, API가 지정한 이미지, 코드 뷰어, 파일 업로드는 없다. 브라우저의 텍스트 렌더링과 서버 DTO 검증은 별개의 방어 경계다.

Host/Origin 검사는 외부 브라우저 출처를 제한하지만 DNS rebinding 또는 OS 수준의 파일 시스템·CPU·메모리 격리를 완전히 제공하지 않는다. 허용된 local target의 symlink 검사도 TOCTOU를 제거하지 않는다. 실제 프로젝트 경로와 규칙 식별자는 로컬 보안 정보일 수 있으므로 응답이나 화면을 외부에 공유하기 전에 검토해야 한다.

## 현재 범위

대시보드는 기존 분석 결과를 표시할 뿐 취약점을 확정하거나 Source→Sink 경로를 생성하지 않는다. Scan 기록 저장, 사용자 계정, 취소, 진행률, 외부 배포, 모델 호출은 제공하지 않는다. UI 사람 대상 사용성 평가와 실제 브라우저 자동화는 별도 검증 결과로 보고한다.
