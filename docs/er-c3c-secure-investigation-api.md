# ER-C3C — Secure Investigation API

## Decision and scope

- Base: `c61b951cacf90185a91d88a7f5207a565d299fe4`
- GitHub run: `41838363397`, `push / completed / success`, Python tests, React dashboard, and Semgrep 1.182.1 integration succeeded; artifacts: 0.
- Contract: dedicated `/api/v2` request/response models. Existing `/api/v1` DTOs and routes remain unchanged.
- Scope: authenticated local HTTP operations over the ER-C3B in-memory registry. No React integration, persistence, GitHub upload, or vulnerability remediation decision.
- The API is enabled only by the official `python -m ai_code_security_analyzer.api` launcher, which explicitly starts loopback Uvicorn with `workers=1` and `reload=False`. `create_app()` and `create_app_from_env()` default the feature to disabled. Unsupported app-factory/ASGI deployments receive `503 unsupported_deployment` on valid v2 operations. This is a constrained supported entry point, not a runtime detector for arbitrary external process managers.
- Deployment approval remains **not approved** for multiple workers/instances, reload, shared multi-user use, or launchers that explicitly opt in without independently proving one worker.

## Endpoints

Every v2 operation uses `POST`, JSON, `X-Local-API-Token`, exact Host allowlisting and, when present, exact Origin allowlisting. Handles are accepted only in JSON bodies; there are no handle-bearing paths or query parameters.

| Endpoint | Input | Success |
| --- | --- | --- |
| `POST /api/v2/investigation-scans` | Exact `ScanRequest` fields: `target_id`, `rule_profile_id` | `200 investigation-scan/v1`, `run_handle`, and the unchanged closed `ScanResponse` under `scan` |
| `POST /api/v2/investigations` | `baseline_handle`, `current_handle` | `201 investigation-session/v1` and `investigation_handle` |
| `POST /api/v2/investigations/evaluate` | `investigation_handle` | `200 finding-disappearance-evaluation/v1` with comparability, assessment, finding IDs/categories, path observations, hypotheses, and fixed limitation codes |
| `POST /api/v2/investigation-release` | `kind` (`run` or `investigation`), `handle` | `204`; absent/already released handles are idempotent |

The scan endpoint calls `_scan_with_manifest()` once, binds the exact response/manifest pair through `register_run()`, and never re-runs Semgrep. It serializes and size-checks a fixed-length-handle envelope before registration, then releases the run if envelope construction or response sending fails. If the caller disconnects during a scan, the scan may finish but the result is discarded before registry admission. Disconnect after registration triggers best-effort release; TTL remains the bound if the transport cannot report failure.

Session creation delegates to the Registry: handles must be active and distinct and refer to the same target and rule profile. It does not claim that a comparison will be comparable. Evaluation delegates to the existing ER-C2 evaluator and validates its result against a closed public schema. A valid `INCOMPARABLE` result is a successful evaluation response; expired/missing handles, corrupt evidence, binding errors, capacity limits and busy evaluation are non-success HTTP errors, never empty finding lists.

## Authentication and request boundary

`ApiBoundaryMiddleware` protects the whole `/api/v2` namespace, including unknown routes and methods, so those paths cannot bypass token validation. The v1 `POST /api/v1/scans` controls are preserved. Duplicate singleton headers are rejected. V2 requests require strict UTF-8 JSON, one top-level object, duplicate-key and NaN/Infinity rejection, bounded nesting/collection sizes, control-character rejection, exact DTO fields and strict string types. Content-Length and actual streamed bytes are capped at 16 KiB; v2 body chunks are capped at 64. The middleware buffers only this bounded body before handing it to FastAPI.

Host and Origin checks run before route dispatch. Approved CORS preflight may omit the token, but requires a configured exact Origin, `POST`, and only the `Content-Type` and `X-Local-API-Token` request headers. It does not read or mutate registry state. CORS credentials remain disabled. All responses retain `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

The token is a local-installation shared secret, not a user identity. Any person/process that can use the same token shares the same authorization boundary. Handles are random registry locators, not authentication credentials. This API does not provide per-person, per-browser, or cross-OS-user isolation.

## Resource and error contracts

Registry limits remain ER-C3B limits: four Runs, two Sessions, 900-second absolute monotonic TTL, 1.25 MiB maximum Run record, 5.25 MiB total Registry bytes, 256 KiB maximum Evaluation output and a single concurrent Evaluation. A scan admission precheck rejects when all four Run slots are occupied; atomic registration remains authoritative under races. No active record is silently evicted. Reads do not extend TTL. Releasing a Run referenced by an active Session is rejected.

Per-app-instance sliding-window limits use bounded fixed state and a monotonic clock: investigation scans 2/minute, Session creation 10/minute, Evaluation 10/minute, Release 30/minute. They are installation-wide, not token/user-specific. Requests rejected by rate limiting do not launch Semgrep or Evaluation.

| Condition | HTTP / fixed error |
| --- | --- |
| Missing/invalid token | `401 unauthorized` |
| Disallowed Host / Origin | `400 host_not_allowed` / `403 origin_not_allowed` |
| Invalid JSON/DTO | `400 invalid_request` |
| Invalid media type | `415 invalid_content_type` |
| Body or response limit | `413 invalid_request` / `413 response_limit_exceeded` |
| Missing, expired, released, or foreign-registry Handle | `404 evidence_unavailable` |
| Target/profile/same-run binding rejected or active Run release | `409 binding_rejected` |
| Registry or rate capacity | `429 resource_limit` |
| Evaluation already running | `409 evaluation_busy` |
| Internal serialization/evaluation failure | `503 internal_unavailable` |
| Unsupported app/ASGI launch configuration | `503 unsupported_deployment` |

Release returns `204` for both first and repeated release so the API does not reveal whether a handle was previously registered. Error bodies contain only fixed codes and never echo a Handle, token, path, exception or Manifest detail.

## Data exposure and lifecycle

The Run response contains only existing `ScanResponse` fields plus the opaque Run Handle in the v2 envelope. It does not expose the C1 `scan_ref`, raw Manifest, registry bytes, digest, absolute server path, code, raw Semgrep JSON, stdout/stderr, rule-file contents or environment. Evaluation exposes only the closed ER-C2 fields; it omits file paths and raw messages. Existing relative Finding paths inside the unchanged `ScanResponse` are inherited from v1, not newly added by the investigation interface.

Handles are returned only where necessary and subsequently accepted in request bodies. They are not written to logs, URL fields, referrers, exports, Markdown or analyst notes. The official launcher disables Uvicorn access logs. A custom launcher that records request bodies is unsupported. Registry ownership remains per app instance; process restart loses all handles. No user memo is retained or copied.

The Registry has no worker sharing. The official launcher explicitly has one worker and no reload. External ASGI factories default the feature off; a caller can opt in only as trusted in-process configuration, and the process manager must still enforce one worker. Multi-worker and multi-instance operation is `MULTI_WORKER_UNSUPPORTED`; production deployment gate is `DEPLOYMENT_GATE_NOT_APPROVED`.

## API-process memory measurement

Measurements used a separate Python 3.12.7 Uvicorn process, macOS 15.7.7 arm64, loopback HTTP, `ps` RSS sampling at 30 ms, and `tracemalloc`. The synthetic maximum-scope workload used 50 valid Findings and 10,000 scanned paths per Run. One canonical Run record measured 1,084,469 bytes (under the 1,310,720-byte cap). Four Runs and two Sessions retained 4,339,096 Registry bytes. It performed two 50-Finding evaluations, then released all records.

| Measurement | Result |
| --- | ---: |
| API process baseline RSS after startup | 14.75 MiB |
| Peak sampled RSS | 80.23 MiB |
| RSS after release | 78.23 MiB |
| Peak traced Python allocations | 12.99 MiB |
| Registry bytes at capacity | 4,339,096 bytes |
| Registry after release | 0 Runs / 0 Sessions / 0 accounted bytes |

The process retains allocator memory after release; this is not secure erase. RSS sampling can miss short peaks. The synthetic Run is near, but not equal to, the configured per-record ceiling. The measurement does not establish a hard RSS cap or production host budget. A separate actual-Semgrep HTTP check performed four scans, created two Sessions, evaluated both, and released all state; it confirmed the real scan path but used smaller (~79,911-byte) Run responses. The benchmark temporarily raised only its private scan limiter to four per minute to reach the four-Run Registry cap; production remains 2/minute.

## Validation

- Final full Python suite: `PYTHONPATH=tests uv run --locked python -m pytest -q` — 646 passed, 28 skipped, 1 existing Starlette/AnyIO deprecation warning, 191.41 seconds.
- `uv lock --check` and `git diff --check` passed.
- Frontend regression already completed against this backend-only worktree: Node 24.22.2 / npm 11.19.1; TypeScript passed, Vitest 180 passed, production build passed, Chromium 49 passed (including axe and responsive checks), WebKit 2 passed, Safari QA automation 7 passed, and real FastAPI–Semgrep–Chromium E2E 2 passed. No frontend source was changed in ER-C3C.
- Added API tests cover end-to-end fake-service HTTP flow, exact v2 envelope, shared/shared-only findings, release, expired handles, cross-app registry isolation, unsupported deployments, token/duplicate headers, Host/Origin, strict JSON duplicate keys/NaN/UTF-8/control chars, closed fields, content type/body limit, CORS preflight, rate limiter concurrency, response-send disconnect cleanup, and single-flight Evaluation.
- Actual FastAPI + Semgrep 1.182.1 HTTP E2E used a synthetic project: baseline A/B then A/C. It verified `shared`, `currentOnly`, `baselineOnly`, `UNDETERMINED`, no second Semgrep execution during evaluation, and released handles are unavailable.
- ER-C3B Registry and C1/C2 tests remain in place. Serializer now also rejects a Manifest whose canonical bytes exceed C1's 1 MiB limit before Registry admission; this closes a case where the Registry could otherwise retain data that its strict deserializer would later reject.
- Fake/ASGI tests are unit/in-process validation; the measured Uvicorn HTTP process and actual Semgrep test are separate evidence.
- Full Python, Semgrep CI suite, frontend, Chromium, WebKit, axe, browser E2E, and Safari QA results are recorded after final execution below.
- Real macOS Safari manual acceptance remains pending; VoiceOver, iOS Safari and manual 200% zoom are not verified in this backend-only phase.
- Exact-SHA GitHub Actions for the new local commit is pending user push; it is not represented as passed.

## ER-C3D readiness and remaining limits

The authenticated local API and bounded registry flow are implemented. ER-C3D can integrate against the closed v2 contracts only after exact-SHA GitHub CI succeeds. It must keep handles in component memory, send them only in POST bodies, clear them on release/expiry/restart, and display unavailable/incomparable distinctly. Multi-user isolation, multi-worker sharing, durable recovery, a hard RSS limit, and production deployment approval are not provided.
