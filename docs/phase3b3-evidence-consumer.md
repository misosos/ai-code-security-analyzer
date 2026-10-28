# Phase 3B-3: Validated Evidence Consumer Boundary

## Consumer API

`consume_evidence_summary(summary, finding, *, scan_result, evidence=None, rules_file=None, trusted_rules_directory=None)` is the only consumer entry point. The `scan_result` argument is required syntactically; an explicit `None` means scan state is unavailable and is never promoted to completed. Taint inputs must be supplied again when consuming a taint summary.

The function invokes the Phase 3B-2 `validate_evidence_summary()` path, which recomputes the Phase 3B-1 Gate from the supplied Finding, ScanResult, TaintEvidence and current trusted rule file. It then requires exact summary equality. There is no summary-only overload, `trusted` flag, validation skip argument, or caller-provided claim list. Any mismatch, missing source input, unexpected validation exception, or oversized result raises the fixed `evidence_consumer_rejected` error without returning a partial result.

## Returned result

`ValidatedEvidence` is a frozen bounded snapshot. Its ordinary constructor requires a private module factory token and has no `trusted=True` or validation-skip parameter; `validation_status` is a computed output field, not constructor input. This is a same-process API guard, not a Python sandbox: deliberate code can inspect private objects or use low-level Pydantic construction. Consumers must obtain results from the function and must not trust deserialized/manually constructed instances. It contains the Finding and rule identifiers, Finding kind, scan and association state, verification status, supported claim records, restricted claim records, aggregate reason/provenance/limitation codes, and bounded engine metadata.

- `allowed_claims` contains complete `SummaryClaim` records only for Gate-supported claims; per-claim reason codes, provenance and limitations are retained.
- `supports(ClaimType)` is a fixed membership query. `decision_for()` and `reasons_for()` report the existing Gate result. `limitations_for()` preserves partial-scan limitations even when a low-level individual-match claim is supported.
- Every non-supported claim remains in `restricted_claims` with its exact decision and reason codes. The consumer does not recalculate or promote a claim.
- Ambiguous Finding/TaintEvidence association rejects the whole consumer operation. Ordinary `unavailable`, `insufficient_evidence` and `unsupported_claim` entries do not invalidate an otherwise consistent summary; they remain restricted.

The output is capped at the existing 16 KiB EvidenceSummary limit. It excludes code, file paths, raw Semgrep messages and free-form diagnostics. A validated Finding remains `unverified`; confirmation is never created.

## Reuse, TOCTOU and trust limits

Validation applies to the supplied inputs at the time of the consumer call. The call checks the current trusted rule digest again; a rule file modified after summary creation causes the old summary to be rejected. The check does not prove which bytes Semgrep read atomically during the earlier scan. The application also has no source-file content digest in the Finding/ScanResult contract, so it cannot prove that analyzed source files remain unchanged. Callers must not reuse a consumer result for another Finding or scan; a later consumption must call the consumer again.

The returned Pydantic object is a same-process data structure, not a signature, authorization token, or Python sandbox. Consumers should obtain it from `consume_evidence_summary()` and should not treat deserialized or manually constructed output as evidence of a completed validation.

## Verification

Unit tests cover taint, pattern and unclassified summaries; restricted Source/Sink/trace claims; partial, failed and missing scan states; changed rule digest; changed Finding/ScanResult; altered claim decision/reasons/provenance; omitted/duplicate/added claims; ambiguous Finding identity; JSON round-trip with and without original inputs; safe error behavior; canary/path exclusion; output bounds; and immutability.

The existing Semgrep OSS 1.182.1 integration test runs the consumer over all 13 taint results and 11 baseline pattern results from synthetic A–L fixtures. No Ollama or external API is called. CI configuration is unchanged because the Python job runs all tests and the Semgrep job already requires this integration test. These synthetic results validate the structural policy only, not semantic security accuracy. OS-level network isolation remains outside the application's guarantee.
