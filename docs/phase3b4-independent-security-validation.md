# Phase 3B-4: Independent evidence pipeline security validation

## Scope and method

This review tests the existing Phase 3B-1 Gate, 3B-2 summary, and 3B-3 consumer. It adds no policy engine or data contract. Unit-test expectations are fixed in the test module before invoking the Gate: for the synthetic taint fixture, only match reported, taint rule match reported, source/sink pattern declared, and match location observed are allowed; for the baseline pattern fixture, only match reported is allowed. Source location, sink argument, flow trace, sanitizer match/effectiveness, and vulnerability confirmation must remain restricted.

The tests exercise claim promotion, altered partitions and provenance, cross-Finding/evidence reuse, scan-state changes, malformed scan metadata, duplicate Findings, same-location different-rule Findings, rule-file changes and symlink replacement, error/canary disclosure, and direct model construction paths. Existing Phase 3A synthetic fixtures are also run with Semgrep OSS 1.182.1 through Finding, TaintEvidence, Gate, Summary, and Consumer.

## Findings

No production security boundary defect was reproduced. No production code was changed. Altered or omitted claims, promoted claims, changed Finding/ScanResult inputs, mismatched taint evidence, ambiguous duplicate Findings, stale rule digests, and a rule path redirected outside the trusted rules root are rejected by recomputation or the existing Gate. Rejections return the fixed consumer error and no partial allowed-claim set.

The fixed policy oracle is checked independently of Gate output. Expected taint and pattern supported sets match. Partial scans can preserve a specifically observed match, declaration, and match location, while the complete-scan taint claim stays restricted. Failed or inconsistent scans support no match claim.

## Explicit limits

- A rule file changed after summary construction is rejected while changed; if the exact original bytes are restored, its digest and declaration match again and consumption succeeds. The digest proves current byte equality, not historical scan-time bytes or a change history.
- Two independent `ScanResult` objects with structurally identical fields cannot be distinguished as separate executions. The current contract has no scan-run identity or signature. Reuse across identical inputs therefore cannot be ruled out as an execution-identity matter; the consumer verifies structural equivalence, not provenance of process execution.
- The consumer does not receive source files or a source digest. Changing a source file after summary construction is not detected by this API. The result only revalidates its supplied Finding, scan, evidence, and current trusted rule declaration.
- Comparing a changed Finding with the original ScanResult is rejected. If a caller forges both Finding and ScanResult consistently in memory, the current types do not attest either to raw Semgrep output. The boundary assumes trusted in-process producers and is not an authenticity mechanism.
- Normal `ValidatedEvidence` construction and `model_validate` are guarded, but Pydantic `model_construct`, private factory token introspection, or arbitrary Python execution can bypass the guard. Such objects must not be trusted; no same-process Python sandbox is claimed.
- The frozen result contains immutable tuples and frozen claim models. It is a bounded structural snapshot, not semantic validation of security meaning.

These are documented assurance limits, not vulnerabilities in the stated consumer contract. No scan identity token, source snapshot system, or signature mechanism was added.

## Verification

The independent test module uses only synthetic values and records these limits as explicit outcomes. Existing Semgrep integration remains the execution-backed check for 13 taint and 11 baseline pattern results. Actual model calls, external APIs, remote rules, and user repositories are excluded. CI workflow and public Finding/AIReview/CLI/JSON contracts remain unchanged.

Validation on the current change:

- Independent security matrix: 38 passed.
- Required Semgrep integration command: 7 passed, 0 skipped, on Semgrep OSS 1.182.1.
- Full suite: 358 passed, 28 skipped, 0 failed. All 28 skips are explicitly gated local Ollama evaluation tests; no Ollama opt-in variable was set.
