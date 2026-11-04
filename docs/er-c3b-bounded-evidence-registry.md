# ER-C3B — Bounded Investigation Evidence Registry

## 1. 목적과 시작 Gate

ER-C3B는 ER-C1의 `ScanResponse`/`ScanEvidenceManifest` 쌍을 앱 프로세스 메모리에 잠시 보존하고, 서로 다른 두 Run만 ER-C2 Evaluator에 전달하는 내부 기능이다. 공개 API, Finding 해결 판정, UI, 파일/DB 저장은 추가하지 않았다.

- 기준 및 부모 SHA: `a08609f0b169bc7f5a5c5d5f9eab7b919bcc3d2a`
- GitHub Actions Run: `41822387237`
- 이벤트/상태/결과: `push / completed / success`
- Python tests and CLI, React dashboard, Semgrep 1.182.1 integration: success
- Artifacts: 0
- GitHub `main` 및 `origin/main`: 기준 SHA와 일치
- 시작 판정: `ER_C3B_START_GATE_GO`
- 작업 경로/브랜치: `/tmp/ai-csa-er-c3b-evidence-registry`, `research/er-c3b-evidence-registry`

## 2. ER-C3A ADR 적용 및 한도 결정

적용 사항:

- Process-local bounded memory, canonical JSON bytes, app instance별 Registry
- C1 `scan_ref`를 보존하며 Run Handle 및 Investigation Handle은 별개 32-byte CSPRNG 값
- Handle digest만 색인에 저장하며 Handle은 locator이고 인증 수단이 아님
- 15분 절대 `time.monotonic()` TTL, 세션 만료는 Run 두 개 중 더 빠른 만료 시각과 연동
- 유효 항목은 자동 eviction하지 않음. 초과 시 신규 등록 거부
- Evaluation 결과는 보관하지 않음. 프로세스 재시작 시 복구 없음
- 한 프로세스 안에서만 공유하며, 사람별 권한 격리를 제공하지 않음

C3A는 Run당 `5 MiB + 64 KiB`, 전체 `20 MiB` 또는 `21 MiB` 예산을 후보로 제시했다. 이 값은 최대 API 설정치만 더한 보수적 상한이라 실제 `ScanResponse` 스키마에서 도달 가능한 크기를 반영하지 않았다. 최대 길이 필드와 50개 Finding을 사용해 유효한 Response를 만들고 C1의 100,000개 scanned path 및 Manifest 1 MiB 제한을 적용해 측정했다.

| 측정치 | 시작/구성 | 관찰값 |
|---|---:|---:|
| ScanResponse canonical JSON | 유효 최대 필드 합성값, Finding 50개 | 217,609 bytes |
| ScanEvidenceManifest canonical JSON | `paths.scanned` 100,000개, C1 한도 안 | 962,978 bytes |
| 한 Run envelope payload | Response + Manifest + 계약 envelope | 약 1.18 MB |
| Registry 보존 bytes | 최대 합성 Run 4개 + Session 2개 및 metadata | 4,723,850 bytes |

초기 측정은 저장소의 `scripts/benchmark_investigation_registry_memory.py`에서 `ER_C3B_BENCHMARK_PHASE=before`를 지정해 Python 3.12.7/macOS 별도 프로세스에서 수행했다. RSS는 Darwin의 `ru_maxrss` bytes 단위를 사용했다.

| 단계 | RSS / peak | `tracemalloc` |
|---|---:|---:|
| import 이후 baseline | 33,865,728 bytes | baseline 128 bytes |
| Response 2개 + Manifest 2개 + Bundle 2개를 구성·평가 | peak 91,406,336 bytes | peak 18,220,478 bytes |

Registry 구현 후 같은 합성 생성기를 사용해 Run 4개를 등록하고 Session 2개를 만들었으며, 2 Run을 역직렬화해 한 건의 Evaluation을 수행했다. 이후 모든 Run/Session을 해제하고 3회 반복 등록·해제를 수행했다.

| 단계 | RSS / peak | `tracemalloc` |
|---|---:|---:|
| import 이후 baseline | 33,931,264 bytes | baseline 128 bytes |
| Run 4개 보존 + Session 2개 | Registry 4,723,850 bytes | 현재 4,727,140 / peak 15,803,352 bytes |
| 두 Run 복원 및 Evaluation | peak RSS 103,120,896 bytes | peak allocation 26,856,765 bytes |
| Evaluation 결과 Finding | 50 | Evaluation 약 5.11초 |
| 해제 후 추적 할당 | RSS peak는 OS high-water mark라 감소를 의미하지 않음 | 13,030 bytes |
| 3회 반복 등록·해제 후 | RSS peak 변화 없음, Registry bytes 0 | 현재 13,146 bytes |

RSS는 이 합성 부하의 측정값이지 전체 API 프로세스나 모든 입력에 대한 강제 상한이 아니다. Python allocator가 RSS를 OS에 반환하거나 비밀값을 안전 삭제한다고 보장하지 않는다. C3A의 후보보다 낮춰 다음 제한을 적용했다.

| 자원 | C3B 제한 | 초과 처리 |
|---|---:|---|
| Run 수 | 앱 인스턴스당 4 | 활성 Run 보존, 신규 등록 `RESOURCE_LIMIT` |
| Run envelope | Run당 1.25 MiB | Run 전체 등록 거부 |
| 전체 Registry byte | 5.25 MiB (Run payload + Run metadata + Session metadata) | 활성 자료 eviction 없이 거부 |
| Manifest wire object | 1 MiB, C1 제한 유지 | 손상/초과 거부 |
| Session 수 | 앱 인스턴스당 2 | 신규 Session 거부 |
| Session metadata | 각 8 KiB, 전체 16 KiB 상한 | Session 생성 거부 |
| 절대 TTL | Run/Session 각 900초 | 조회 시 TTL 연장 없음 |
| Evaluation 동시성 | 1 | `EVALUATION_BUSY` |
| Evaluation 출력 | C2 256 KiB | 전체 출력 거부, 일부 결과 반환 금지 |

1.25 MiB Run 한도는 유효 최대 ScanResponse 217,609 bytes, C1 Manifest 최대 1 MiB 및 envelope 여유를 합친 값이다. 5.25 MiB aggregate는 네 개의 최대 Run(5 MiB)과 metadata 여유를 포함한다. 측정 harness의 Run은 약 1.18 MB여서 4.72 MB가 보존됐다. 실제 제품에서 별도 ASGI/다중 요청 동시 부하 시험은 하지 않았다.

## 3. 구현 계약

신규 내부 모듈: `src/ai_code_security_analyzer/investigation_evidence_registry.py`

`investigation-evidence-registry/v1`의 Run payload는 닫힌 `{contract_version, response, manifest}` JSON envelope다. `ScanResponse`는 기존 closed Pydantic 모델로 strict JSON 검증 후 복원한다. Manifest는 모든 top-level/nested key를 정확히 확인하고 C1 dataclass와 enum을 허용목록 기반으로 복원한다. UTF-8, duplicate key, NaN/Infinity, 알 수 없는 필드, 잘못된 타입/개수/버전, 비정규 canonical encoding, 1 MiB 초과 Manifest, 1.25 MiB 초과 envelope를 거부한다. pickle/eval은 사용하지 않는다.

Run 등록은 `bind_run_evidence()` 이후 직렬화하고, C1 `scan_ref` 중복을 거부한다. 원문 Handle은 응답 호출자에게 한 번만 반환될 내부 locator이며 Registry에는 SHA-256 digest를 저장한다. Registry는 Response/Manifest를 합친 bytes와 고정 metadata만 보유한다. 반환·평가 시 strict 복원 및 binding을 재검증하고, 복원된 scan_ref/target/profile이 Registry metadata 및 Session의 두 Run reference와 일치하는지 확인한다.

Session은 내부 무작위 `investigation_ref`, handle digest, baseline/current C1 scan_ref, target/profile 및 TTL metadata만 가진다. Response, Manifest 사본 또는 Evaluation 결과를 저장하지 않는다. 동일 Run, 다른 Target/Profile, 만료/미등록 Run은 거부한다. Semgrep version, partial/failed 상태 및 omitted count는 기존 C2 Evaluator의 보수적 Gate에 맡긴다.

`get_run`과 Evaluation은 짧은 lock 구간에서 immutable bytes를 pin한다. 평가 중 Release는 `EVALUATION_BUSY`로 거부하고, 만료는 논리적으로 즉시 효력이 있으며 결과 반환 직전에 재검증한다. 해제는 idempotent다. 활성 Session이 참조하는 Run의 해제는 거부한다. TTL cleanup은 다음 Registry 작업에서 수행되며 별도 janitor는 없다. 만료된 값은 정리 전이라도 사용할 수 없다.

고정 내부 오류는 `EVIDENCE_UNAVAILABLE`, `BINDING_REJECTED`, `RESOURCE_LIMIT`, `INTERNAL_UNAVAILABLE`, `EVALUATION_BUSY`다. 오류 문자열은 코드만 포함하고 Handle/경로/원본 JSON을 포함하지 않는다. 만료·미등록·해제는 같은 `evidence_unavailable` 오류로 외부 노출이 가능하도록 묶었다.

## 4. 앱 소유권과 공개 계약

`create_app()` 호출마다 새 `app.state.investigation_registry`를 생성한다. 모듈 전역 Singleton은 없다. 기존 `/api/v1/scans`는 계속 `ScanService.scan()`을 호출하며 Manifest를 응답에 추가하지 않는다. 새 endpoint, DTO, 프런트엔드 코드, 파일/DB 저장은 없다. C3B Registry는 내부 구현이며 기존 ScanResponse의 필드 집합을 변경하지 않는다.

기존 launcher `python -m ai_code_security_analyzer.api`는 `127.0.0.1`, `reload=False`, `workers=1`로 명시 실행한다. 이번 구현은 다른 외부 launcher의 다중 worker/다중 서버 Registry 공유를 지원하거나 시작 시 차단하지 않는다. 따라서 이 Registry 기능을 사용하는 배포는 단일 worker/reload 비활성 조건으로 제한해야 하며, 이를 강제하는 공개 API가 아직 없으므로 운영 승인 상태가 아니다. 서로 다른 app instance 및 프로세스는 Registry를 공유하지 않고 재시작 후 기존 Handle은 복구되지 않는다.

현재 API의 X-Local-API-Token은 사용자별 신원을 보장하지 않는다. 새 Registry 메서드는 비공개 내부 함수이며 HTTP 인증/인가를 자체 제공하지 않는다. C3C는 새 버전 endpoint마다 Token, Host/Origin, no-store, body/요청률 상한과 고정 오류 코드를 적용해야 한다. Handle은 인증 수단으로 취급하면 안 된다.

## 5. 테스트와 독립 Oracle

신규 테스트 `tests/test_investigation_evidence_registry.py`는 strict serializer, 중복 JSON key/비유한 수/unknown fields, binding, handle 분리, 앱 인스턴스 격리, TTL, 용량, no-eviction, release, 동시 Evaluation, 만료 중 Evaluation, 손상 payload, 부분/생략 검사 및 실제 Semgrep A/B→A/C를 다룬다. 실제 CLI 테스트는 합성 프로젝트와 저장소의 신뢰된 baseline 규칙만 사용한다.

| C3A Oracle | 지원 상태 | 비고 |
|---|---|---|
| 1–3 정상 Run 등록 및 2 Run 연결 | `TESTED` | 실제 Semgrep 포함 |
| 4 동일 Run, 5 다른 Target, 6 다른 Profile | `TESTED` | Session 생성에서 거부 |
| 7 허위 Handle, 8 만료, 9 삭제 후 재사용, 10 반복 Release | `TESTED` | 고정 unavailable/멱등 동작 |
| 11 프로세스 재시작 | `STRUCTURAL_ONLY` | 새 app instance 독립성 확인, 실제 프로세스 재기동 시험은 미실행 |
| 12 Run 4개 제한, 13 개별 byte cap, 14 aggregate cap | `TESTED` | 작은 cap 주입 및 실제 4개 측정 |
| 15 Session 2개 제한 | `TESTED` | 활성 Session 유지 |
| 16 동시 Evaluation | `TESTED` | 결정적 Event hook, 두 번째는 busy |
| 17 평가 도중 만료, 18 평가 중 Release | `TESTED` | 결과 discard / release 거부 |
| 19 HTTP disconnect | `NOT_APPLICABLE` | C3C HTTP 경로 전 |
| 20–23 Token/Origin/Host | `NOT_APPLICABLE` | 신규 경로 미구현; 기존 middleware 미변경 |
| 24–25 공유 Token 사용자 격리 | `UNSUPPORTED` | 사용자별 신원 모델 없음 |
| 26–27 raw Manifest/Canary 노출 | `PARTIAL` | Registry/error repr 비노출 단위 검증, HTTP/log 경로는 C3C |
| 28 Finding 0건, 29 skip 미수집, 31 partial | `INHERITED` | C2 Evaluator 계약 유지; partial/omitted 회귀 테스트 포함 |
| 30 Response 직렬화 실패 | `TESTED` | admission 전 binding/serializer 거부 |
| 32 omitted 결과 | `TESTED` | C2 incomparable 반환 |
| 33 payload 변조 | `TESTED` | strict parser 오류, 빈 Evaluation 아님 |
| 34 Handle/scan_ref 충돌 | `PARTIAL` | scan_ref 및 handle 충돌 경로 테스트; 내부 ref 충돌은 CSPRNG retry |
| 35 다중 worker | `UNSUPPORTED` | 단일 process 전용, 런타임 차단은 미구현 |
| 36 CORS preflight/non-JSON body | `NOT_APPLICABLE` | 신규 HTTP endpoint 없음 |

`paths.scanned`는 Semgrep이 보고한 경로 관찰일 뿐 전체 검사·규칙 적용 완료 증거가 아니다. 실제 평가 결과는 Finding 집합 차이와 C2 limitation을 보존하며 Finding 미관찰을 수정·해결로 해석하지 않는다.

## 6. 실행 검증

환경: Python 3.12.7, uv lock 의존성, Semgrep 1.182.1, Node.js 24.22.2. Benchmark 재실행은 `uv run --locked python scripts/benchmark_investigation_registry_memory.py`, 초기 두 Bundle 측정은 `ER_C3B_BENCHMARK_PHASE=before uv run --locked python scripts/benchmark_investigation_registry_memory.py`를 사용한다. 실제 macOS Safari/VoiceOver/iOS/200% 검수는 이번 Backend 작업 범위에 포함되지 않았다.

검증 결과:

| 검증 | 결과 |
|---|---|
| ER-C3B Registry / serializer + 실제 A/B→A/C 테스트 | 23 passed; 실제 Semgrep 포함 |
| ER-C1 Manifest / ER-C2 Evaluator / Parser / Adapter / ScanService 및 전체 Python pytest | 631 passed, 28 skipped, 1 warning |
| CI와 동일 Semgrep 1.182.1 통합 묶음 | 46 passed, 1 warning |
| uv lock --check | passed |
| Node.js / npm | Node 24.22.2, npm 11.19.1 |
| TypeScript / Vitest / Production build | passed; Vitest 180 tests |
| Chromium / axe | 49 passed; axe 시나리오 포함 |
| WebKit | 2 passed |
| 실제 FastAPI–Semgrep–Chromium E2E | 2 passed; 격리 포트, 합성 프로젝트 |
| Safari QA 자동 회귀 | 7 passed; 자체 합성 서버 사용 |
| 1440×900 UI 위치 | Finding list Y=724.44px, first row Y=784px |
| git diff --check | passed |

## 7. 남은 위험 및 ER-C3C Gate

- 측정은 단일 macOS Python subprocess의 합성 최악 fixture다. Linux RSS, 동시 HTTP request, server base load, 전체 API 프로세스 hard RSS cap은 검증하지 않았다.
- 100,000 path를 가진 50 Finding 비교는 이 환경에서 약 8초 걸렸다. 동시성 1로 제한했으나 향후 API timeout/rate limit을 별도 정해야 한다.
- Python bytes/object 해제는 secure erase가 아니며 allocator RSS 반환도 보장하지 않는다.
- Registry는 app instance/process local이다. 다중 worker 시작 차단과 단일 worker 운영 검증이 없다.
- C3B에는 HTTP route, token enforcement, 사용별 authorization, handle 전송, UI, client disconnect 처리가 없다.
- Path/Manifest는 내부에 제한 보유되지만 기존 ScanResponse의 상대 경로는 이미 분석 결과에 포함된다.

ER-C3C 공개 API 전제: payload/result cap, strict restore, app-instance 격리, TTL/release, 평가 concurrency, 실제 Semgrep A/B→A/C, 공개 ScanResponse 불변을 검증할 것. 또한 endpoint-level token/Host/Origin/no-store/body-size/rate-limit, single-worker deployment gate, access-log redaction, client disconnect orphan cleanup을 구현·검증해야 한다. 현재 상태에서 C3C 구현 진입은 `CONDITIONAL`; 운영 승인이나 다중 사용자 보장은 아니다.

실제 macOS Safari/VoiceOver/iOS/수동 200% 검수는 수행하지 않았다. 기존 Safari QA 서버는 접근하거나 종료하지 않았다. Linux에서 exact SHA CI는 아직 실행하지 않았으므로 Push 이후 확인 대상이다.

현재 판정: `ER_C3B_BOUNDED_EVIDENCE_REGISTRY_LOCAL_CONDITIONAL_GO`. 공개 API/UI는 미구현이며 운영 승인 상태가 아니다.
