# ER-C3A — Investigation Evidence Lifecycle & Binding Design

## 결정 요약

ER-C3A는 ER-C1의 실행별 Manifest와 ER-C2의 평가기를 실제 재검사 조사 흐름에 연결하기 전 필요한 보존, 수명, 바인딩, 접근 경계를 설계한다. 이번 Phase는 문서 전용이며 저장소, API, DTO, UI, 인증 동작은 구현하지 않는다.

권고 MVP는 **단일 API 프로세스 안의 bounded process-local registry**다. 응답과 Manifest를 함께 검증한 뒤 제한된 canonical JSON bytes로 보관하고, 무작위 run handle은 내부 `scan_ref`를 찾는 locator로만 사용한다. 조사 세션은 두 run reference를 연결하며 결과를 영구 저장하지 않는다. 고정 TTL이 지나거나 명시 해제되면 조회를 거부한다. 프로세스 재시작 후 복구하지 않는다.

이 설계는 사용자별 격리를 제공하지 않는다. 현재 `X-Local-API-Token`은 로컬 설치가 공유하는 자격이며 사용자 계정이 아니다. C3B MVP는 같은 로컬 API 토큰을 가진 요청자를 동일 로컬 분석 주체로 취급하고, 이 제한을 UI 및 운영 문서에 명시해야 한다. 서로 다른 OS 사용자·브라우저 사용자 간 격리가 필요한 배포에는 이 MVP를 사용하지 않는다.

## 1. 시작 Gate와 작업 경계

- 기준 SHA: `b2c61e211908fbad711524c9142ff490e979a46f`
- GitHub Actions Run: `41818945216`
- 이벤트/상태/결과: `push / completed / success`
- GitHub main 및 origin/main: `b2c61e211908fbad711524c9142ff490e979a46f`
- Python tests and CLI: success
- React dashboard: success
- Semgrep 1.182.1 integration: success
- Artifact: 0개
- 시작 판정: `ER_C3A_START_GATE_GO`

작업 worktree는 `/tmp/ai-csa-er-c3a-evidence-lifecycle`, 브랜치는 `research/er-c3a-evidence-lifecycle`이며 origin/main에서 생성했다.

Desktop 원본은 기준 시점에 `c783d2d`였고 원격보다 14개 커밋 뒤였다. 추적 파일 6개에 수정이 있고 미추적 `.taste-skill/`, `output/`, Playwright 자료, UI 캡처와 문서가 있었다. 이 작업에서는 해당 파일을 열람·수정·정리하지 않았다. 기존 ER-C0 worktree는 origin보다 2개, ER-C1 worktree는 1개 커밋 뒤였고 ER-C1/ER-C2 worktree에는 미추적 `.taste-skill/`이 있었다. 이 항목들은 보존했다.

## 2. 현재 구현의 실제 계약

### ER-C1 및 ER-C2

- `ScanService._scan_with_manifest(target_id, rule_profile_id)`는 하나의 Semgrep 실행으로 `(ScanResponse, ScanEvidenceManifest)`를 반환한다. `scan()`은 Manifest를 버리고 기존 `ScanResponse`만 반환한다.
- Manifest에는 새 `secrets.token_urlsafe(24)` scan reference, target/profile ID, status/count/Finding ID, Semgrep 버전과 고정 invocation ID, 선택된 규칙 파일 ID, bounded scope 자료가 있다. 일반 코드 원문, raw Semgrep JSON, 절대 경로, stderr, API token은 포함하지 않는다.
- Manifest 최대 직렬화 크기는 1 MiB, scanned 경로 100,000개, skipped 경로 10,000개, 경로당 1,024 UTF-8 bytes, scope 합계 1 MiB다. 이 크기는 Python 객체 heap 사용량의 측정치가 아니다.
- `paths.scanned`는 Semgrep JSON이 보고한 경로다. 전체 분석 범위 또는 모든 규칙의 처리 완료를 증명하지 않는다. 기본 실행의 `paths.skipped` 부재는 `NOT_COLLECTED`다.
- `RunEvidenceBundle`은 immutable wrapper이며 `bind_run_evidence(response, manifest)`가 구조와 필드 일치를 확인한다. Response 자체에는 scan reference가 없으므로 이 검증은 신뢰된 함수 호출자가 같은 `_scan_with_manifest()` 실행 결과를 즉시 전달하는 경계에 의존한다. 임의의 in-process 호출자에 대한 암호학적 출처 증명은 아니다.
- `evaluate_finding_disappearance(baseline, current)`는 두 bundle의 집합 차이와 제한된 Scope 관찰만 계산하는 순수 함수다. Finding 합집합 최대 100개, 결과 최대 256 KiB다. 고정 ID/경로 외에는 인과·소스 동일성·해결 여부를 추론하지 않는다.
- Manifest와 Evaluation은 현재 호출자가 메모리에 보유한 동안만 존재한다. Registry, DB, 파일, HTTP endpoint 및 브라우저 baseline과의 연결은 없다.

### 현재 API 및 보안 경계

`create_app()`는 `ScanService`를 `app.state.scan_service`에 두고 `/api/v1` Router를 등록한다. `POST /api/v1/scans`는 `service.scan()`을 호출하므로 Manifest에 접근하지 않는다. 공개 `ScanResponse`는 `ClosedModel(extra="forbid")`이며 프런트엔드 `parseScan()`도 정확한 필드 집합을 요구한다. 기존 응답에 handle이나 scan reference를 추가하면 API와 파서 계약이 깨질 수 있다.

`ApiBoundaryMiddleware`는 모든 HTTP 요청에 Host allowlist와 Origin allowlist(Origin이 제공된 경우)를 검사한다. 다만 현재 `X-Local-API-Token`, JSON content type, 16 KiB request body 제한은 정확히 `POST /api/v1/scans`에만 적용된다. `/health`, `/options` 등은 토큰 없이 읽을 수 있다. `SecurityHeadersMiddleware`는 모든 HTTP 응답에 `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, CSP 및 보안 헤더를 적용한다. CORS는 설정된 정확한 Origin만 허용하고 credentials는 비활성이다.

로컬 실행 진입점 `python -m ai_code_security_analyzer.api`는 `127.0.0.1:8765`, `reload=False`로 Uvicorn을 실행하며 `workers`를 지정하지 않는다(기본 단일 worker). 이는 운영자가 다른 ASGI 명령으로 다중 worker를 띄우는 것을 방지하지 않는다. `ScanService`의 `_scan_lock`은 해당 서비스 인스턴스 내 검사 동시성을 제한한다. 모든 프로세스가 공유하는 lock이나 Registry는 아니다.

조사한 실제 경로는 `src/ai_code_security_analyzer/scan_evidence_manifest.py`, `finding_disappearance_evaluator.py`, `services/scan_service.py`, `api/routes.py`, `api/schemas.py`, `api/security.py`, `api/app.py`, `api/__main__.py`, `frontend/src/api/client.ts`, `frontend/src/api/types.ts`, `frontend/src/features/scans/compare.ts`, `frontend/src/app/App.tsx`다. 근거 계약 문서는 ER-C0/C1/C2, Phase 8L 및 Phase 7B 위협 모델이다.

### 브라우저 baseline

Phase 8L의 `ScanSnapshot`은 API 검증된 `ScanResponse`와 응답 도착 시의 `ScanContext`로 구성되며 React component state에만 보관한다. `baselineSnapshot`도 component state다. `localStorage`, `sessionStorage`, IndexedDB를 사용하지 않으며 새 검사 시작/결과 삭제 시 명시적인 초기화 흐름이 있다. Baseline은 Manifest나 scan reference를 포함하지 않는다. 동일 Finding ID, 동일 response 값, 또는 동일 target/profile 값만으로 과거 실행과 새 Manifest를 사후 연결할 수 없다.

## 3. 수명 대안 비교

| 기준 | A. Process-local bounded memory | B. 암호화 local file store | C. Client-held evidence |
|---|---|---|---|
| 보안/노출 | 짧은 프로세스 수명, API 경계를 통하면 비공개. 같은 프로세스 권한의 공격에는 격리 아님 | 재시작 후 보존 가능하나 키·파일 권한·백업·삭제 복잡성이 추가 | 서버 보존 감소. 내부 Scope 경로/Response/Manifest가 브라우저에 직접 노출되고 변조 입력이 서버로 되돌아옴 |
| 구현 복잡도 | 낮음~중간: 용량/TTL/동시성/worker 제한 필요 | 높음: 키 수명·회전, atomic write, crash consistency, 파일 lock, janitor | 중간: serialization, 서명/무결성, 버전 전환, 탭/새로고침 수명 |
| API 호환성 | 별도 인증된 API 버전으로 제한 가능 | 별도 인증 API 필요, 복구/관리 계약 추가 | 전송 크기와 공개 DTO 변경 압력, 엄격 parser 및 client validation 영향 |
| 데이터 최소화 | 제한된 응답·Manifest만 짧게 유지 가능 | 더 긴 보존 및 잔류·백업 위험 | 서버에는 덜 남지만 Browser memory/export/devtools에 더 많이 노출 |
| 디버깅/실무성 | 재검사 간 수분 단위 조사에 적합, 재시작 시 명확히 종료 | 장기 조사에 유리하나 ER-C0/C1/C2 MVP 목적에 과도 | 브라우저 세션 연계가 쉬워 보이나 출처를 신뢰할 수 없고 tampering이 필요 통제 추가 |
| 자원 제한/검증 | byte-count와 고정 레코드 수로 검증 가능. Python 전체 RSS 상한은 별도 측정 필요 | 디스크 quota·정리·키·crash 시험이 추가 | 브라우저별 메모리/탭 종료 동작이 통제 불가하고 서버 재검증 비용은 남음 |
| 실패 영향 | 프로세스 종료 시 증거 손실, fail closed | 키 유실/파일 손상/잔류 위험 | 브라우저 state 손실/수정 또는 다른 검사와 잘못 결합할 위험 |

**결정: A를 ER-C3B의 제한된 로컬 MVP로 선택한다.** ER-C1/C2가 이미 비영속적 내부 자료를 제공하며 실제 목표는 동일한 실행 프로세스 안에서 짧은 재검사 조사다. 이 선택은 다중 worker, 재시작 복구, 사용자별 격리를 제공하지 않는다. 장기 보존 요구가 확인되면 별도 저장소 설계와 개인정보 검토를 거쳐야 한다. Client-held evidence는 신뢰 경계가 약해지므로 사용하지 않는다. Encrypted file store는 키·잔류 위험 대비 현재 이점이 낮아 채택하지 않는다.

## 4. ER-C3B용 데이터 계약

아래는 **설계 타입**이며 현재 구현된 클래스나 공개 JSON이 아니다.

```text
InvestigationEvidenceSessionV1 {
  contract_version: "investigation-evidence-session/v1"
  investigation_ref: InternalRandomId
  session_handle_digest: OpaqueHandleDigest
  baseline_scan_ref: InternalScanRef
  current_scan_ref: InternalScanRef
  target_id: ValidatedTargetId
  rule_profile_id: ValidatedRuleProfileId
  created_monotonic: ProcessLocalMonotonicTime
  expires_monotonic: ProcessLocalMonotonicTime
  lifecycle: ACTIVE | EXPIRED | EVICTED | RELEASED
}
```

세션은 두 Run Record를 참조하며 Run Bundle 또는 Evaluation을 복제하지 않는다. 실행 reference와 조사 reference는 내부 난수 식별자이며 외부로 반환하지 않는다. UI에는 locator인 run handle 및 필요 시 investigation handle만 반환한다. Handle은 인증·인가 수단, 서명, 사용자 ID, scan reference가 아니다.

Run Record 개념:

```text
RunEvidenceRecordV1 {
  scan_ref: InternalRandomId
  run_handle_digest: OpaqueHandleDigest
  target_id: ValidatedTargetId
  rule_profile_id: ValidatedRuleProfileId
  response_manifest_json: BoundedCanonicalUtf8Bytes
  admitted_monotonic: ProcessLocalMonotonicTime
  expires_monotonic: ProcessLocalMonotonicTime
  lifecycle: ACTIVE | EXPIRED | EVICTED | RELEASED
}
```

Run payload는 신뢰된 `_scan_with_manifest()` 경계에서 받은 **정확한 Response/Manifest 쌍**으로부터 닫힌 필드 serializer를 통해 만든다. Python pickle은 금지한다. registry는 immutable bytes를 보유한다. Evaluation 직전에 response는 기존 closed Pydantic schema로, Manifest는 버전이 고정된 명시적 parser로 복원하고 ER-C2 binding 검증을 다시 수행한다. 복원 실패는 정상 빈 응답이 아니라 `INTERNAL_UNAVAILABLE`/`BINDING_REJECTED` 계열로 닫힌다.

세션 생성은 서로 다른 두 ACTIVE run handle을 받아 내부 run record reference를 연결한다. Target ID, Rule Profile ID, Semgrep 버전 및 ER-C2의 기존 비교 Gate는 검사한다. 같은 Run을 baseline/current로 지정하는 것은 거부한다. 공개 응답에는 ER-C2의 고정 상태/제한 코드 및 최소 Finding 결과만 포함하며 원본 Manifest는 반환하지 않는다.

## 5. Provenance, 핸들 및 접근 정책

### Provenance 연결 사슬

1. API v2 scan 경로가 `ScanService._scan_with_manifest()`를 정확히 한 번 호출한다.
2. 반환 직후 `bind_run_evidence(response, manifest)`를 수행한다.
3. 고정 serializer로 응답과 Manifest의 일관성 및 크기를 확인한다.
4. Registry는 Manifest에 이미 있는 C1 `scan_ref`를 그대로 run record의 내부 key로 사용한다. 같은 live Registry 안에서 중복이면 overwrite하지 않고 등록을 거부한다. 새로운 scan reference를 만들어 Manifest에 덧씌우지 않는다. C1 reference는 외부로 반환하지 않는다.
5. 무작위 run handle은 해당 record에 대한 locator digest로만 저장한다. 충돌 시 덮어쓰지 않고 bounded 재시도 후 실패한다.
6. Investigation 생성 시 registry가 handle을 해석해 원본 record를 pin하고, 세션이 두 C1 internal scan reference를 연결한다. 호출자가 Response/Manifest를 제출해 registry 값을 대체할 수 있는 API는 제공하지 않는다.
7. Evaluation 직전에 복원 및 binding 검증 후 ER-C2 순수 함수를 실행한다.

이는 정상 애플리케이션 경로의 우발적 혼합과 클라이언트 객체 위조를 막는 설계다. 동일 프로세스 내부 메모리를 임의 수정할 수 있는 공격자에 대한 MAC 기반 provenance 보장은 아니다. Registry 자체의 무결성을 같은 OS 사용자/프로세스 권한 밖의 공격자로부터 보장하지 않는다.

### Handle

- Run handle 및 investigation handle은 각각 CSPRNG 32 random bytes를 base64url 인코딩한 불투명 값(통상 43자)으로 생성한다. 내부 C1 `scan_ref` 및 새 내부 `investigation_ref`와 별개다.
- URL path/query, 로그, 오류 설명, referrer, 분석가 메모 또는 다운로드에 넣지 않는다. JSON body에서만 전달한다. 응답에는 no-store/no-referrer를 유지한다.
- Registry는 원문 handle 대신 SHA-256 handle digest를 lookup key로 저장할 수 있다. Digest는 인증이나 위조 방지 증명이 아니며 같은 handle을 매핑하기 위한 키다. 새로운 MAC/HMAC 프로토콜은 도입하지 않는다.
- 등록 충돌은 overwrite하지 않는다. Expired/Released/없는 handle은 평가하지 않는다. 외부 오류는 존재 여부를 구별하지 않는 고정 `evidence_unavailable`로 통일할 것을 권고한다.
- `EVICTED`는 lifecycle vocabulary에 예약하되 기본 정책에서 살아 있는 Run/Session을 eviction하지 않으므로 정상 경로에서는 emit하지 않는다. 향후 명시적인 관리자 폐기 기능이 추가될 때만 별도 사유와 감사를 정의한다.

### 인증·인가

- 모든 새 조사 작업 endpoint는 `X-Local-API-Token`을 검증해야 한다. CORS `OPTIONS` preflight는 브라우저가 token 값을 보내지 않으므로 예외로 두되, exact Host/Origin/CORS method/header 검사만 수행하고 Registry를 조회·변경하지 않는다. 현재 middleware처럼 POST scans에만 적용된다고 가정하지 않는다.
- 기존 Host 검사, exact Origin 정책, CORS credentials 비활성, `no-store`, `no-referrer`, CSP를 그대로 적용한다. 브라우저가 보내는 Origin은 있다면 정확한 allowlist와 일치해야 한다.
- 새 JSON body에도 현재 16 KiB 상한 또는 더 작은 고정 상한을 적용한다. 제한은 Content-Length와 실제 수신 byte 모두에 강제한다.
- Handle은 locator일 뿐이다. API token 없이 handle만 아는 주체는 접근할 수 없어야 한다. 그러나 현재 token은 설치 공유 비밀이므로 같은 token을 가진 두 로컬 사용자/탭은 구별되지 않는다. 본 MVP의 authorization principal은 “설정된 로컬 API token을 가진 로컬 설치 사용자”이며 사람별 소유권은 아니다.
- 브라우저별/사용자별 isolation이 요구되면 C3B 진입을 중단하고 별도 사용자 신원·세션/권한 모델을 설계한다. 임의로 브라우저 쿠키를 추가하거나 token을 handle로 대체하지 않는다.
- 로컬 API는 현재 HTTP loopback이므로 OS 사용자와 같은 권한을 가진 로컬 프로세스가 환경 token을 얻거나 브라우저 메모리를 조사할 수 있는 위험을 제거하지 않는다. 허용 Origin은 악성 원격 웹 페이지의 브라우저 접근을 낮추지만 로컬 프로세스 인증은 아니다.

## 6. Retention, 자원 및 동시성 결정

### ER-C3B 기본 한도 제안

현재 상한은 ScanResponse JSON 설정값 최대 4 MiB, 기본 1 MiB이며 Manifest 표현은 최대 1 MiB다. 이 두 값에 envelope 직렬화 overhead 64 KiB를 더해 Run payload당 5 MiB + 64 KiB를 예산으로 잡는다. 이를 근거로 초기 **설계 예산**은 다음과 같다.

| 자원 | C3B 시작 한도 | 처리 |
|---|---:|---|
| Run record 수 | 프로세스당 4 | 만료된 항목만 먼저 정리. 살아있는 항목을 조용히 제거하지 않고 `RESOURCE_LIMIT` 거부 |
| Run payload | record당 5 MiB + 64 KiB canonical UTF-8 bytes | 초과 시 등록 거부. 일부 Finding/경로를 잘라 저장하지 않음 |
| 전체 Run payload | 21 MiB canonical bytes | 초과 등록 거부 |
| Investigation session 수 | 프로세스당 2 | 기존 유효 세션을 자동 eviction하지 않고 거부 |
| 세션 metadata | session당 8 KiB, 합계 16 KiB | 초과 거부 |
| Evaluation 동시 실행 | 1 | 이미 실행 중이면 추가 요청을 고정 busy/resource 오류로 즉시 거부 |
| Evaluation 결과 | 기존 ER-C2 256 KiB | 초과 시 결과 전체를 거부/`INCOMPARABLE`; 부분 결과 금지 |
| 요청 body | 최대 16 KiB | 실제 수신 크기 제한 포함 |
| Run 생성 | 프로세스당 2회/분, 한 번에 1개 | scan single-flight 유지, 초과는 고정 `RESOURCE_LIMIT` |
| Session 생성/Evaluation | 각 프로세스당 각각 10회/분 | 초과는 고정 `RESOURCE_LIMIT`; token별 사용자 분리는 하지 않음 |
| Release | 프로세스당 30회/분 | 멱등 release 유지, 초과는 고정 `RESOURCE_LIMIT` |

이 byte accounting은 보유 payload의 정확한 UTF-8 크기 경계이지 Python 전체 RSS 상한이 아니다. Registry는 JSON bytes 자체를 보유하여 Python tuple/string graph의 크기를 지속 보유하지 않도록 한다. 해석 시 최대 두 Run을 복원하고 동시 평가를 하나로 제한한다. C3B에서 합성 최대 응답을 사용한 RSS/peak allocation 시험을 실행하고 API 프로세스의 전체 RSS 예산을 측정해야 한다. RSS 목표를 통과하지 못하면 Run 수/응답 한도를 낮추기 전에는 구현 Gate를 통과하지 않는다. Python allocator가 메모리를 OS에 즉시 반환하거나 bytes가 secure erase된다고 보장하지 않는다.

### 만료와 명시 해제

- Run TTL: Registry 등록 시점부터 **15분 절대 TTL**.
- Investigation TTL: 생성 시점부터 15분 또는 연결된 두 Run 중 먼저 만료되는 시점 중 더 이른 시각.
- TTL은 `time.monotonic()` 기반이며 요청 때마다 연장하지 않는다. UTC wall clock은 사용자 표시/로그를 위해 필요할 경우 별도 취급하되 만료 판단에 쓰지 않는다.
- 각 등록·조회·해제·용량 계산 전에 만료 항목을 제한적으로 정리하고, 필요하면 단일 bounded janitor를 둔다. 장시간 새 요청이 없어도 프로세스가 멈추거나 종료되면 TTL sweep이 즉시 실행된다고 보장하지 않는다.
- 해제는 멱등적으로 처리한다. 이미 해제/만료된 locator는 동일한 외부 `evidence_unavailable` 응답으로 닫고 정상 결과를 돌려주지 않는다. 세션 해제는 세션 참조를 제거한다. Run release는 살아 있는 세션이 참조 중이면 거부하거나 해당 세션을 먼저 명시 해제하도록 해야 한다.
- Capacity pressure는 expired purge 후에도 공간이 없으면 거부한다. 유효 세션/기준을 LRU로 예고 없이 제거하지 않는다. client disconnect로 회수할 수 없는 record는 TTL과 총량 한도가 제한한다.
- 프로세스 종료, crash, 재시작, OS 재부팅 시 모든 record/session은 소실된다. stale handle은 고정 unavailable 오류를 받는다. 자동 복구, 디스크 fallback, 이전 browser snapshot과의 재결합은 없다.

### 동시 접근

Registry의 짧은 dictionary/byte-accounting 변경은 `threading.Lock` 아래 원자적으로 수행한다. 느린 Semgrep scan과 evaluator는 전역 registry lock을 점유하지 않는다. Session 생성 시 두 record를 한 임계 구역에서 lookup하고 reference를 pin한다. Evaluation 중 release/expiry는 새 조회를 막고, in-flight 참조가 끝날 때까지 bytes를 유지한다. Evaluation 결과를 반환하기 전 만료/release가 확인되면 결과를 폐기한다. 조회·평가 횟수에도 process-local rate/concurrency 상한이 필요하다.

현재 ScanService scan lock은 검사 인스턴스당 single-flight다. C3B Registry도 단일 프로세스 내에서만 보인다. 별도 Uvicorn worker, reload supervisor, 다중 server instance에서 같은 handle을 조회하는 것을 지원하지 않는다. C3B의 정식 local launcher는 worker=1, reload=false를 명시하고, 지원하지 않는 배포 구성은 시작 시 차단하거나 명확한 운영 오류를 내야 한다. 프로세스 전역 singleton만으로 다중 worker 지원을 주장하지 않는다.

## 7. 등록·응답 원자성 및 실패 상태

HTTP 서버는 소켓/브라우저가 응답 전체를 실제 수신했는지 Scan/Registry 코드만으로 확정할 수 없다. 따라서 C3B는 아래 실패 모델을 사용한다.

1. Scan 실행 및 Response/Manifest 결합 실패: 등록 없음. 기존 scan 오류/실패 상태를 유지.
2. API v2 응답 envelope의 strict serialization/크기 검증 실패: Registry에 등록하지 않음.
3. Registry admission 실패: 정상 scan envelope를 handle 없이 성공처럼 반환하지 않고 고정 resource/unavailable 오류로 종료.
4. Registry 등록 후 ASGI 응답 전달/connection 실패: orphan run은 고정 15분 TTL 및 4-record/20 MiB 상한으로 회수. 응답 성공을 가장하거나 무제한 재시도하지 않음.
5. 조사 평가 중 disconnect: 가능한 경우 계산 취소, 아니면 bounded 평가 완료 후 결과 객체 참조를 놓음. 저장된 Evaluation은 없음.
6. 응답 serialization 이후 전송 중 실패: 해당 session/run은 TTL까지 남을 수 있음. 이는 분산 트랜잭션으로 제거할 수 없으며 설계된 한계다.

외부 오류 코드 후보는 고정된 closed enum으로 한다. 내부 상태와 오류는 분리한다.

| 내부 상태/조건 | 외부 동작 후보 | 규칙 |
|---|---|---|
| `ACTIVE` | 성공 | 모든 binding/auth/TTL 검사 통과 |
| `EXPIRED`, `EVICTED`, `RELEASED`, `NOT_FOUND` | `evidence_unavailable` | locator 존재 여부를 구별하지 않음 |
| `BINDING_REJECTED` | `evidence_unavailable` 또는 고정 409 | 대상/profile/run 불일치 상세를 과도하게 노출하지 않음 |
| `RESOURCE_LIMIT` | 503 + 고정 코드 | 정상 빈 Evaluation으로 대체 금지 |
| `INTERNAL_UNAVAILABLE` | 503 + 고정 코드 | parser/serializer/registry 오류 세부와 경로를 숨김 |
| 같은 run을 양쪽에 제출 | 고정 400/409 | ER-C2 비교 수행 안 함 |
| partial/failed/omitted 검사 | ER-C2 기존 `INCOMPARABLE` 규칙 | 빈 결과나 완료 비교로 승격 금지 |

## 8. 후속 API, UI 및 Phase 8L 연계

### API 결정 후보

| 선택 | 장점 | 문제 | 결정 |
|---|---|---|---|
| A. 기존 `/api/v1/scans` 응답에 handle 추가 | UI 호출 변경 작음 | `ScanResponse` closed schema 및 `parseScan()` exact keys 위반, 기존 API 소비자 호환 깨짐 | 거부 |
| B. 완전히 교체된 새 일반 scan API | 응답 계약 분리 | 기존 제품 전체 전환 범위가 커짐 | ER-C3B MVP에 불필요 |
| C. 별도 versioned investigation API | 기존 scan contract 유지, opt-in으로 증거 비용 발생, 제한된 DTO 제공 | API middleware 인증 확장과 별도 UI 흐름 필요 | **채택 권고** |
| D. 기존 API + 숨겨진 내부 handle exchange | 단계적 전환처럼 보임 | v1 ScanResponse와 정확한 execution 관계가 없어서 안전하게 exchange할 방법이 없음 | 거부 |

C3B 후보 인터페이스(구현 전 schema review 필요):

- `POST /api/v2/investigation-runs`: 명시적으로 조사 기능을 선택한 경우만 scan 실행. 입력 `{target_id, rule_profile_id}`. 결과 `{scan: ScanResponse, run_handle}`. strict response parser가 envelope와 nested 기존 ScanResponse를 모두 검증한다.
- `POST /api/v2/investigations`: `{baseline_run_handle, current_run_handle}`. 정확한 두 Registry Run을 바인딩하고 조사 세션을 만들며 평가 요약과 `investigation_handle`을 반환한다.
- `POST /api/v2/investigations/evaluate`: `{investigation_handle}`. 서버에 보관된 두 원본 Run을 다시 복원·검증해 평가한다. 결과는 저장하지 않는다.
- `POST /api/v2/investigation-release`: `{kind, handle}`의 고정 enum. 명시 세션/Run 해제. body 크기 제한 및 동일 인증 경계를 적용한다.

모든 조사 작업 경로는 새 API version, exact DTO, `X-Local-API-Token` 매 요청, Host/Origin, no-store, no-referrer, JSON body 제한, 고정 오류 코드, TTL/용량 제한을 갖는다. CORS preflight는 token 예외이며 Registry 상태 변경이 없어야 한다. Handle은 URL에 넣지 않는다. UI는 만료/재시작/용량/비교 불가 상태를 각각 안전하게 표시하되 빈 평가로 위장하지 않는다.

### Phase 8L 연계

Phase 8L의 브라우저 `ScanSnapshot`과 이전에 저장한 기준 응답은 서버 Handle이 없다. 기존 v1 snapshot을 Manifest에 자동 연결하지 않는다. 사용자가 기능을 명시적으로 켠 시점부터 두 검사를 모두 조사 전용 v2 경로로 새로 수행해야 한다. 각 run handle은 scan response와 같은 component state에 하나의 immutable record로 묶는다. baseline 설정은 해당 두 요소를 같이 보유한다. 새 current 검사가 도착하면 새로운 handle을 보유하며 과거 분석가 review 상태/메모는 초기화 정책 그대로 유지한다.

비교 기준 해제/화면 결과 삭제 시 연관 Investigation Session과 더는 쓰지 않는 Run을 명시 해제한다. page unload/네트워크 단절 시 DELETE 성공을 보장할 수 없으므로 TTL은 계속 필요하다. 브라우저 새로고침 후 저장소에서 handle을 복원하지 않는다. 서버 Registry에 값이 살아 있어도 클라이언트 locator가 없는 경우 이를 자동 탐색/연결하는 기능은 제공하지 않는다.

## 9. 공개 데이터 최소화와 개인정보

API/UI에 필요한 공개 정보는 제한한다.

- 비교 가능 여부와 고정 차단 코드
- Finding ID 및 `currentOnly/shared/baselineOnly`
- ER-C2의 제한된 `PathObservation`, 개별 가설 상태, 고정 limitation code
- 평가 contract version
- 제한된 target/profile 표시값이 필요하면 기존 options label/ID 계약과 별도 검토

기본적으로 제외:

- Raw Manifest, raw Semgrep JSON, stdout/stderr
- 소스 원문·매치 조각·환경변수·API token
- 서버 절대 경로, 규칙 파일 본문, 내부 rule digest
- 파일명/상대 경로의 불필요한 복사
- 자유형 Semgrep message 및 예외 문자열
- OS username, process ID, host filesystem metadata

ER-C2 결과는 baseline Finding ID, 제한된 PathObservation과 코드만으로도 조사 안내를 제공할 수 있다. 사용자가 실제 후속 검토를 위해 위치를 필요로 하는 경우에도 현재 ScanResponse에 이미 제공되는 상대 경로보다 많은 경로를 공개하지 않는다. 경로는 소스 구조를 노출할 수 있으므로 필요한 화면에서만 보여주며 URL·로그에 넣지 않는다.

Registry logging은 count, 고정 status/error code, elapsed bucket만 허용하고 handle/raw payload/경로는 기록하지 않는다. ASGI access logging이 켜질 수 있는 다른 launcher도 `/api/v2` body나 query를 기록하지 않도록 검증해야 한다. 현재 `api.__main__`은 access log를 끄지만 이는 모든 외부 Uvicorn 구성의 통제가 아니다.

## 10. 위협 모델 및 잔여 위험

| 위험/공격 조건 | 신뢰 경계 및 영향 | C3B 예방 통제/검증 | 잔여 위험 |
|---|---|---|---|
| IDOR/다른 Run 조회 | handle 탈취·추측으로 타 검사 증거 열람 | 256-bit random handle, token + Origin/Host, registry binding, body 전용 handle, cross-target tests | 동일 공유 token principal 안의 사람별 격리 없음 |
| Handle 추측/재사용 | 임의 locator로 정상 결과 접근 | CSPRNG, 상수 시간 token 비교, TTL, released/expired 거부, rate limit | token을 보유한 로컬 주체의 권한은 동일 |
| Handle URL/Referer/로그 유출 | 서버/access/browser history 로그에 남음 | URL 금지, JSON body, no-store/no-referrer, body logging 금지 | 브라우저 memory/devtools/악성 same-origin 코드 위험 |
| 서로 다른 실행 증거 혼합 | 클라이언트 제출 객체를 내부 실행 증거로 오인 | 응답에서 받은 객체를 server registry로 다시 보내지 않고 handles만 보냄; 내부 원본 bytes 재검증 | 프로세스 내부 임의 코드 실행/메모리 변경 공격은 범위 밖 |
| Target/profile 혼합 | 타 프로젝트/규칙 비교 오판 | session create/evaluate 시 ER-C2 gate 재실행 | 선택 profile 동일성이 rule bytes 동일성은 아님 |
| Shared token 사용자 혼동 | 다른 tab/local user가 같은 handle 사용 | 공개 범위를 설치 수준 주체로 제한, per-user 보장 금지 | 다중 analyst 격리 필요시 MVP 부적합 |
| TOCTOU | scan 도중 파일/규칙 변화 | 현재 C1의 재검사 통제 유지, 이번 보존은 실제 Manifest/Response만 bind | C1 source snapshot이 없고 TOCTOU 제거 불가 |
| Registry race/조기 삭제 | evaluate와 release/expiry 경쟁 | lock 아래 pin+lookup, in-flight lease, output 전 상태 재확인 | 프로세스 종료는 즉시 모든 state 상실 |
| 메모리 고갈/조회 폭주 | 요청자가 많은 최대 Scan을 반복 등록/평가 | record/aggregate byte cap, session cap, scan single-flight, eval semaphore/rate cap | 전체 API process RSS와 별도 모듈 메모리도 함께 측정 필요 |
| TTL 우회/슬라이딩 수명 | 반복 요청으로 임의 장기 보존 | 절대 monotonic TTL, 조회로 연장 금지, 명시 정책 | OS suspend/monotonic clock 플랫폼 의미 C3B에서 시험 |
| 비정상 저장 payload | 내부 직렬화/파싱 오류가 원문 노출 | JSON only, exact fields, strict types/count/size, fixed error | 같은 프로세스 악성 코드에 대한 신뢰 방어는 아님 |
| 실패를 빈 결과로 표시 | stale/unavailable evidence가 “Finding 없음”처럼 보임 | 외부 `evidence_unavailable`, 불완전/INCOMPARABLE 분리, UI 회귀 테스트 | UI 번역 오류는 별도 테스트 필요 |
| 민감 경로/Canary 노출 | 경로 또는 원문이 응답·로그에 나타남 | closed output DTO, 경로 최소화, canary 비노출 및 로그 검사 | 기존 ScanResponse가 이미 상대 경로를 일부 공개함 |
| 브라우저 저장소/새로고침 | stale handle 또는 메모리 자동 복구 | local/session storage 금지, reload 뒤 미복구, 재검사 안내 | 브라우저 프로세스 종료 전까지 메모리 존재 |
| 다중 Worker/인스턴스 | 다른 worker에서 handle이 없음 또는 다른 record 참조 | worker=1 운영 gate, startup/runtime check 검토 | 여러 서버/고가용성 지원 불가 |
| 서버 재시작/오래된 locator | 클라이언트가 stale handle 전송 | Registry는 비영속, 고정 unavailable, 자동 복구 금지 | 사용자에게 재검사 필요 |

## 11. 정상/실패 워크플로

### 정상

1. 분석가가 UI에서 재검사 조사 기능을 명시적으로 선택한다.
2. 첫 v2 조사 실행이 ScanResponse/Manifest를 생성·결합하고 Run handle을 반환한다.
3. 해당 응답과 handle을 UI component state 한 객체로 보유하고 기준으로 지정한다.
4. 소스가 변경된 뒤 같은 조사 기능으로 두 번째 v2 실행을 수행한다.
5. 두 번째 Run handle을 응답과 함께 state로 보유한다.
6. 사용자의 명시 비교 동작에서만 두 handle을 조사 세션으로 연결한다.
7. 서버는 동일 target/profile/version 및 ER-C2 gate를 통과한 정확한 두 저장 bundle을 평가한다.
8. UI는 제한된 관찰, 검증 상태와 한계를 표시한다. Finding 미관찰을 수정/해결로 바꾸지 않는다.
9. baseline 해제 또는 조사 종료 시 session/run release를 요청한다. 실패해도 TTL이 정리한다.

### 실패 흐름

| 상황 | 내부 결과 | UI 문구 후보 |
|---|---|---|
| v1 기준 스냅샷 | 연결할 Registry run 없음 | “이 기준은 조사 증거가 보존된 검사 결과가 아닙니다. 비교 조사를 위해 새 기준 검사를 실행하세요.” |
| 기준/current 만료 또는 서버 재시작 | `EXPIRED`/`NOT_FOUND` → 외부 `evidence_unavailable` | “조사 증거를 사용할 수 없거나 만료되었습니다. 새 검사를 실행해야 합니다.” |
| 다른 Target/profile 또는 동일 Run | `BINDING_REJECTED` | “선택한 검사 문맥으로 비교할 수 없습니다.” |
| 허위/타인 handle, token 누락/오류 | 인증/조회 거부, 본문/존재 여부 최소화 | “조사 요청을 인증할 수 없습니다.” 또는 일반 연결 오류 |
| 허용되지 않은 Origin/Host | 기존 boundary 거부 | 기존 안전 고정 오류 |
| Resource limit | `RESOURCE_LIMIT` | “임시 조사 저장 공간이 가득 찼습니다. 기존 조사 해제 또는 만료 후 다시 시도하세요.” |
| partial/failed/omitted | ER-C2 `INCOMPARABLE` / 제한 코드 | “검사가 완료되지 않았거나 결과가 생략되어 부재 원인을 비교할 수 없습니다.” |
| 등록 후 전송 중 연결 끊김 | orphan run ACTIVE, 고정 TTL로 정리 | UI에는 받은 응답이 없으므로 일반 연결 실패; 자동 재연결/handle 추측 금지 |
| 병렬 release/evaluate | 새 조회 거부; in-flight pin 해제 후 제거 | “조사 증거가 더 이상 사용 가능하지 않습니다.” |
| serialization/Registry 손상 | `INTERNAL_UNAVAILABLE` | “조사 증거를 처리할 수 없습니다. 새로운 검사를 수행하세요.” |

## 12. ER-C3B 독립 보안 Oracle

테스트 데이터는 합성 대상, synthetic canary, fake clock 및 deterministic registry seam을 사용한다. 실제 토큰/코드/사용자 경로를 로그에 넣지 않는다.

| # | 시나리오 | 기대값과 차단할 오류 |
|---:|---|---|
| 1 | 정상 첫 조사 Run | 정확한 Response/Manifest pair만 등록, 새 handle |
| 2 | 정상 두 번째 Run | 서로 다른 internal scan_ref와 run handle |
| 3 | 정상 두 Run 연결 | 같은 target/profile/version 및 ER-C2 gate 통과 |
| 4 | 동일 Run을 양쪽으로 지정 | reject; 자기 자신과의 비교 금지 |
| 5 | 다른 Target | binding reject; cross-project evidence 혼합 방지 |
| 6 | 다른 Rule Profile | reject; 분석 조건이 다른 결과 비교 금지 |
| 7 | 허위 random handle | not-found와 타 handle을 구분 노출하지 않음 |
| 8 | Expired run handle | evaluation 없음, unavailable |
| 9 | 명시 해제된 handle | 재사용/부활 거부 |
| 10 | 이미 해제된 handle을 다시 해제 | 멱등 unavailable/safe success; record 재생성 금지 |
| 11 | 프로세스 재시작 뒤 이전 handle | unavailable; disk/클라이언트에서 복구 금지 |
| 12 | run record 최대 4개 도달 | 활성 entry 보존, 새 등록 거부 |
| 13 | 개별 5 MiB byte 상한 초과 | 해당 run 전체 거부; 경로/Finding 일부 잘라내기 금지 |
| 14 | aggregate 20 MiB 상한 초과 | 활성 entry eviction 없이 거부 |
| 15 | session 최대 2개 도달 | 유효 세션 자동 삭제 없이 거부 |
| 16 | 요청 2개가 동시에 같은 session 평가 | concurrency cap 준수; bundle 변형/중복 계산 제한 |
| 17 | 평가 도중 만료 | 결과 전달 전 expiry 검사 후 폐기 |
| 18 | 평가 중 session/run release | 새 lookup 차단, in-flight lease 정리 후 제거 |
| 19 | scan response 연결 중 client disconnect | orphan은 15분/상한 내에서만 유지 |
| 20 | API token 누락 | 모든 v2 조사 경로 401; handle만으로 접근 불가 |
| 21 | 잘못된 API token | constant-time token compare, 상세 노출 없음 |
| 22 | 허용되지 않은 Origin | boundary 403 전에 Registry 조회/변경 없음 |
| 23 | 허위 Host | boundary reject; Registry 접근 없음 |
| 24 | 두 browser tab에서 동일 공유 token/handle | 정책상 동일 설치 principal; 사용자별 분리 보장 주장 금지 |
| 25 | 서로 다른 공유-token 사용자 | 계정 격리 기대를 시험에서 명시적으로 unsupported 처리 |
| 26 | Raw Manifest 응답/로그 검사 | raw JSON 및 절대 경로 0건 |
| 27 | 민감정보 Canary 삽입 | HTTP body/error/log에서 code/secret/path canary 0건 |
| 28 | 정상 응답 Finding 0건 | 빈 Finding 차이는 가능하나 안전/해결 판정 금지 |
| 29 | `paths.skipped` 미수집 | `NOT_COLLECTED`; skip 없음으로 해석하지 않음 |
| 30 | ScanResponse serialization 실패 | Registry admission 이전 실패 |
| 31 | partial/failed scan | ER-C2 제한/INCOMPARABLE; 정상 완전 비교로 승격 금지 |
| 32 | omitted Finding 양수 | 비교 차단/INCOMPARABLE; 생략 결과 무시 금지 |
| 33 | Registry payload tamper/잘못된 JSON | strict binding reject; 빈 Evaluation으로 fallback 금지 |
| 34 | 중복 handle/internal reference 충돌 | overwrite 거부, 전체 admission 실패 |
| 35 | 멀티 worker에서 다른 프로세스 조회 | 실행 구성 gate 거부 또는 명시 unsupported, 다른 registry로 fallback 금지 |
| 36 | CORS preflight 또는 비 JSON body | 실제 path별 auth/content-type/size 정책 준수 |

Oracle의 안전성 지표는 “원인 정답률”이 아니다. 핵심 금지 오판은 expired/unavailable/partial/omitted run을 정상 빈 Evaluation으로 반환하는 것, 타 run bundle을 연결하는 것, Finding 부재를 해결로 표현하는 것 각각 0건이어야 한다.

## 13. ADR 결정 기록

| ADR | 결정 | 상태 | 근거/제한 |
|---|---|---|---|
| C3A-1 저장 방식 | Process-local bounded registry, canonical JSON bytes | `DECIDED FOR MVP` | C1/C2 수명과 맞고 영구 저장/키 관리 없음 |
| C3A-2 Registry 소유자 | FastAPI app instance state에 한 개 registry; ScanService와 분리 | `DECIDED FOR MVP` | app factory 테스트 격리. 모듈 전역 singleton 금지 |
| C3A-3 Run identity | 내부 C1 scan_ref는 유지; 별도 무작위 run handle locator | `DECIDED` | scan_ref 외부 노출 및 handle 인증 금지 |
| C3A-4 Session identity | 내부 investigation_ref와 별도 무작위 session handle | `DECIDED` | 두 run ref만 연결하고 bundle 복제 금지 |
| C3A-5 Provenance | service 실행 pair를 admission 후 immutable bytes로 보유, retrieve 시 strict parse/rebind | `DECIDED FOR TRUSTED APP FLOW` | 암호학적 in-process provenance 보장이 아님 |
| C3A-6 보존/만료 | Run 15분, session 15분 또는 earliest run expiry; absolute monotonic TTL | `PROPOSED FIXED MVP VALUE` | C3B에서 fake clock, suspend, cleanup 검증 필요 |
| C3A-7 자원 | 4 runs / 5 MiB per run / 20 MiB aggregate / 2 sessions / 1 evaluator | `PROPOSED FIXED MVP BUDGET` | RSS peak 시험 통과가 구현 Gate |
| C3A-8 접근 제어 | 모든 v2 조사 route마다 기존 local token + Host/Origin 검사; 공유 설치 principal | `DECIDED WITH SCOPE LIMIT` | 사람별·브라우저별 격리 없음; 필요 시 C3B HOLD |
| C3A-9 Handle 운반 | JSON body만, URL/log/referrer/export 금지 | `DECIDED` | no-store/no-referrer 지속 적용 |
| C3A-10 API 버전 | 별도 versioned investigation-only endpoints; v1 ScanResponse 불변 | `RECOMMENDED` | exact new schema 및 middleware tests 필요 |
| C3A-11 UI | 기존 Finding comparison 안에서 opt-in; 조사 전용 검사 2회 요구 | `RECOMMENDED` | 기존 v1 baseline은 연결 불가, refresh 후 자동 복구 안 됨 |
| C3A-12 Worker scope | 단일 Uvicorn worker, reload=false, 단일 process | `DECIDED FOR MVP` | 다중 worker/instance unsupported |
| C3A-13 영속성 | restart/crash 후 evidence loss, no recovery | `DECIDED` | 사용자 재검사 필요 |
| C3A-14 실패 | unavailable/resource/binding을 빈 평가로 바꾸지 않음 | `DECIDED` | fixed error vocabulary; 세부 정보 비노출 |
| C3A-15 Python RSS cap | serialized byte budget + record limit 후 RSS 실측 | `OPEN IMPLEMENTATION GATE` | Python heap/ASGI buffers 전체 고정치 미측정. C3B 이전 benchmark 필수 |
| C3A-16 여러 사람 사용 | 지원하지 않음 | `DECIDED` | 사용자별 identity/authorization이 없으므로 운영을 제한 |

## 14. ER-C3B 진입 순서와 Gate

권장 구현 순서:

1. Strict serializer/parser 및 5 MiB payload 상한. pickle 금지, Response/Manifest pair binding 단위 테스트.
2. Thread-safe bounded Registry 구현: 최대 count/bytes, monotonic TTL, explicit release, idempotency, expiry cleanup, no eviction of active items.
3. Run/session handle 생성, digest lookup, 충돌·만료·동일 Run·cross-target/profile 차단.
4. app factory가 Registry를 소유하고 test app마다 격리. global singleton 금지.
5. 새 조사 API version 및 middleware에 모든 route의 token/Origin/Host/body limit 적용.
6. Registry 저장 후 response serialization/전달 실패와 orphan cleanup을 ASGI 수준에서 검증.
7. 동시 evaluate/release/expiry, multi-thread requests, single-worker startup gate 및 restart 시험.
8. 최소 공개 Evaluation schema, UI opt-in 2-run flow, 새 조사 모드가 아닌 v1 snapshot 거부, 새로고침/clear/expiry 메시지 구현.
9. 전체 ER-C2/Python/API/frontend/e2e 회귀 및 privacy canary 검증.

ER-C3B 착수 Gate:

- [x] 저장 방식, lifecycle owner, handle/run/session 구분 설계
- [x] binding, shared-token 권한 범위, endpoint version 방향 설계
- [x] TTL/count/byte 한도 및 fail-closed 정책 제안
- [x] 단일 worker/restart 정책과 36개 test oracle
- [x] 데이터 최소화 및 로그 정책
- [ ] 최대 합성 Response/Manifest로 RSS/peak allocation benchmark와 배포 RSS 예산 합의
- [ ] 지원 대상 macOS/Python/Uvicorn 런타임에서 monotonic/suspend/cleanup 동작 시험
- [ ] C3B API별 보안 검토 및 UI의 사용자 승인 문구

따라서 C3B는 설계상 구현 가능하나, **RSS 계측 및 실행 환경 검증 전에는 구현 완료/운영 승인으로 판정하지 않는 제한적 진입**만 가능하다. 해당 측정 목표가 충족되지 않거나 사용자별 격리가 필요하면 ER-C3B는 `HOLD`해야 한다.

## 15. 사실 기반 검증 및 미실행 항목

실제 코드/문서 확인:

- ER-C1의 Manifest 필드 및 상한, `_scan_with_manifest()`/`scan()` 반환 분리
- ER-C2 bundle binding 및 evaluator 상한·차단 동작
- `/api/v1/scans`의 `service.scan()` 경로, exact ScanResponse schema, response size 검사
- token 검사가 현재 `POST /api/v1/scans`에만 적용되는 점
- 모든 요청에 적용되는 Host/Origin boundary, 응답 `no-store`/`no-referrer`, CORS credentials 비활성
- loopback launcher host `127.0.0.1`, port `8765`, `reload=False`, worker 미지정
- 프런트엔드 baseline이 component memory에만 있고 persistence API를 호출하지 않는 점
- Phase 8L에서 새 검사 시 analyst review 상태 초기화 및 자동 승계 금지

이 Phase는 설계 전용이다. 저장소 구현, HTTP API 테스트, RSS 측정, 실제 Safari, VoiceOver, iOS 또는 전체 Python/Frontend/Semgrep 회귀는 실행하지 않았다. 이는 문서 산출물의 수용 기준이 아니므로 `NOT_RUN`이다. 기준 CI만 원격 exact SHA에서 확인했다. 신규 조사 API 및 UI는 `NOT_IMPLEMENTED`다.

`git diff --check`: PASS. 추적 파일 변경은 없고 신규 설계 문서 한 파일만 생성했다.

## 최종 판정

- 시작 Gate: `ER_C3A_START_GATE_GO`
- ER-C3A 설계: `ER_C3A_INVESTIGATION_EVIDENCE_LIFECYCLE_LOCAL_CONDITIONAL_GO`
- ER-C3B 구현: `ER_C3B_IMPLEMENTATION_NOT_STARTED` (RSS 측정 전 제한적 진입 권고)
- 공개 API: `NOT_IMPLEMENTED`
- UI 연동: `NOT_IMPLEMENTED`
- 취약점 해결 판정: `NOT_SUPPORTED`
- 실제 Safari 수동 검수: `SAFARI_USER_ACCEPTANCE_PENDING`
