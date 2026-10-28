# Phase 3B-2: EvidenceSummary contract and validation

## Purpose and trust boundary

`EvidenceSummary` is a bounded internal transfer representation of the complete Phase 3B-1 Evidence Sufficiency Gate result for one Finding. It does not perform a second sufficiency policy, generate natural-language security claims, call a model, or alter a Finding. A summary object by itself is not an authenticity token. A consumer must call `validate_evidence_summary()` with the original Finding and scan inputs; that function reruns the existing Gate and requires exact summary equality.

## Contract

The frozen, `extra="forbid"` Pydantic model contains:

- opaque Finding ID in the parser's bounded identifier format and rule ID;
- classification `pattern`, `taint`, or `unclassified`;
- the original ScanStatus, or `null` when no scan status was supplied;
- TaintEvidence association (`exact`, `ambiguous`, `unavailable`, or `not_applicable`), Semgrep engine/version metadata, match observation decision, trusted declaration status, and Finding verification status;
- every fixed ClaimType exactly once, partitioned into `supported_claims` and `restricted_claims`;
- the exact decision, reason codes, per-claim provenance, Finding link and limitations copied from the Gate;
- deterministic aggregate provenance and limitations.

The validator checks complete, duplicate-free partitioning and rejects unsupported decisions in the supported list, supported decisions in the restricted list, duplicate reason/provenance aggregates, mixed Finding IDs, and invalid classification/association combinations. The source claim set is not caller-provided: `build_evidence_summary()` invokes the Gate itself. Validation independently rebuilds the expected summary from the original inputs. Altered or omitted results fail closed with a fixed error.

## Classification and retained limits

- **Pattern:** no `TaintEvidence` was supplied. A baseline match remains a pattern match.
- **Taint:** the existing Gate verified a trusted Source or Sink rule declaration (or taint match claim). This describes rule analysis, not an actual Source location or exploit path.
- **Unclassified:** taint evidence was supplied, but its declarations or association could not be verified.

All unsupported and unavailable claims remain in `restricted_claims`, with their original `ClaimDecision`, reason codes, provenance and limitations. In particular, `unavailable` does not mean a flow does not exist. `unsupported_claim` does not mean false positive. `FLOW_TRACE_ABSENT`, empty, unsupported, malformed and other unavailable states remain distinguishable through the Gate reason codes. Partial scan status is preserved with the Gate's `scan_partial` limitation; failed scans do not gain a supported match claim.

When no TaintEvidence exists (for example, an ordinary pattern Finding), TaintEvidence association is `not_applicable`; its scan match is represented separately by `match_observation_status`. A structurally linked TaintEvidence can have an exact association while its rule declaration remains unverified, such as a digest mismatch. Trusted rule declarations are rechecked against the current pinned local rule file and digest. The summary carries the Gate's `rule_file_at_scan_time_unproven` limitation: the current file digest does not prove which bytes Semgrep read atomically during the scan.

## Privacy and size

The contract excludes source paths, code, Semgrep message/snippet, arbitrary diagnostics and raw JSON. It only permits parser-format opaque IDs, bounded rule identifiers, enums and fixed codes. The serialized summary is capped at 16,384 UTF-8 bytes; overflow raises instead of dropping fields. On the synthetic single-result fixture, observed JSON sizes were 4,007 bytes for a taint summary and 3,277 bytes for a pattern summary. These are fixture measurements, not universal maxima.

Summaries are internal and are not added to public CLI output or JSON. They are not sent to Ollama or any external service. Finding status is copied descriptively and is never changed; confirmation is not created.

## Validation

Synthetic unit tests check Gate parity, full-claim completeness, field/reason/provenance tampering, omission, duplication, wrong-Finding association, rule-hash mismatch, pattern/taint distinction, partial/failed scans, canary exclusion, deterministic serialization and size limits. The existing Semgrep 1.182.1 A–L integration test now builds and revalidates summaries for each of its 13 taint results and 11 baseline pattern results. Those fixture counts describe policy behavior, not real-world security accuracy.

No CI workflow change was needed: the Python job already runs the full pytest suite and the Semgrep job already requires `tests/test_semgrep_taint_evaluation.py`. Neither job invokes a model. The application still does not provide OS-level network isolation.
