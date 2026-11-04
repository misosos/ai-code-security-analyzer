"""Synthetic-only, isolated-process RSS/allocation benchmark for ER-C3B.

Run with: uv run --locked python scripts/benchmark_investigation_registry_memory.py
No source files, API tokens, Semgrep output, or network services are used.
"""

from __future__ import annotations

import gc
import json
import os
import resource
import time
import tracemalloc
from dataclasses import asdict

from ai_code_security_analyzer.api.schemas import ApiFinding, ScanResponse
from ai_code_security_analyzer.evidence_sufficiency import ClaimDecision, ClaimType, EvidenceReason
from ai_code_security_analyzer.evidence_summary import FindingKind
from ai_code_security_analyzer.finding_disappearance_evaluator import (
    bind_run_evidence,
    evaluate_finding_disappearance,
)
from ai_code_security_analyzer.investigation_evidence_registry import RunEvidenceRegistry
from ai_code_security_analyzer.models import Severity
from ai_code_security_analyzer.scan_evidence_manifest import (
    EvidenceStatus,
    ScopeEvidence,
    create_scan_evidence_manifest,
    new_scan_ref,
)
from ai_code_security_analyzer.semgrep_adapter import ScanStatus


def _rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Darwin reports bytes; Linux and the other supported Unix runner report KiB.
    return int(peak if os.uname().sysname == "Darwin" else peak * 1024)


def _synthetic_response() -> ScanResponse:
    claims = tuple(ClaimType)
    reasons = tuple(EvidenceReason)
    restricted = tuple(
        {"claim_type": claim, "decision": ClaimDecision.UNAVAILABLE, "reason_codes": reasons[:8]}
        for claim in claims
    )
    findings = tuple(
        ApiFinding(
            finding_id=f"semgrep:{index:024x}",
            rule_id="r" + "x" * 255,
            severity=Severity.HIGH,
            verification_status="unverified",
            finding_kind=FindingKind.PATTERN,
            file_path="a" * 512,
            line_number=2_147_483_647,
            evidence_validation_status="validated",
            supported_claims=claims,
            restricted_claims=restricted,
            validation_error_code="e" * 64,
        )
        for index in range(50)
    )
    return ScanResponse(
        scan_status=ScanStatus.COMPLETED,
        completed=True,
        semgrep_version="1.182.1",
        finding_count=50,
        displayed_finding_count=50,
        omitted_finding_count=0,
        severity_counts={severity: sum(item.severity is severity for item in findings) for severity in Severity},
        issues=(),
        findings=findings,
        limitations=(),
    )


def _synthetic_run() -> tuple[ScanResponse, object]:
    response = _synthetic_response()
    paths = tuple(f"{index:06d}" + ("x" if index < 60_000 else "") for index in range(100_000))
    scope = ScopeEvidence(
        completeness_status=EvidenceStatus.UNVERIFIED,
        paths_object_present=True,
        scanned_field_present=True,
        scanned_status=EvidenceStatus.OBSERVED,
        scanned_paths=paths,
        reported_scanned_count=len(paths),
        skipped_status=EvidenceStatus.NOT_COLLECTED,
        skipped_paths=(),
        skipped_rules_status=EvidenceStatus.NOT_COLLECTED,
        skipped_rules_count=None,
        errors_status=EvidenceStatus.NOT_COLLECTED,
        errors_count=None,
        limitations=("scanned_paths_do_not_prove_complete_analysis",),
    )
    manifest = create_scan_evidence_manifest(
        scan_ref=new_scan_ref(),
        target_id="target",
        rule_profile_id="baseline",
        semgrep_version="1.182.1",
        exit_code=0,
        scan_status="completed",
        finding_count=response.finding_count,
        displayed_finding_count=response.displayed_finding_count,
        omitted_finding_count=response.omitted_finding_count,
        finding_ids=tuple(item.finding_id for item in response.findings),
        selected_rule_file_id="security-baseline.yml",
        scope_evidence=scope,
    )
    return response, manifest


def run_before() -> dict[str, object]:
    response, manifest = _synthetic_run()
    first = bind_run_evidence(response, manifest)
    second_response, second_manifest = _synthetic_run()
    second = bind_run_evidence(second_response, second_manifest)
    evaluation = evaluate_finding_disappearance(first, second)
    return {
        "retained_run_objects": 2,
        "response_json_bytes": len(response.model_dump_json().encode("utf-8")),
        "manifest_json_bytes": len(json.dumps(asdict(manifest), ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
        "evaluation_findings": len(evaluation.findings),
    }


def run_after() -> dict[str, object]:
    registry = RunEvidenceRegistry()
    handles: list[str] = []
    register_seconds: list[float] = []
    sizes: tuple[int, int] | None = None
    for _ in range(4):
        started = time.perf_counter()
        response, manifest = _synthetic_run()
        if sizes is None:
            sizes = (
                len(response.model_dump_json().encode("utf-8")),
                len(json.dumps(asdict(manifest), ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
            )
        handles.append(registry.register_run(response, manifest))
        register_seconds.append(time.perf_counter() - started)
        del response, manifest
        gc.collect()
    first_session = registry.create_session(handles[0], handles[1])
    second_session = registry.create_session(handles[2], handles[3])
    stored_bytes = registry.stored_bytes
    started = time.perf_counter()
    evaluation = registry.evaluate(first_session)
    evaluation_seconds = time.perf_counter() - started
    registry.release_session(first_session)
    registry.release_session(second_session)
    for handle in handles:
        registry.release_run(handle)
    gc.collect()
    residual_before_repeat = tracemalloc.get_traced_memory()[0]
    for _ in range(3):
        response, manifest = _synthetic_run()
        handle = registry.register_run(response, manifest)
        del response, manifest
        registry.release_run(handle)
        gc.collect()
    return {
        "retained_run_objects": 4,
        "session_objects": 2,
        "response_json_bytes": sizes[0] if sizes else 0,
        "manifest_json_bytes": sizes[1] if sizes else 0,
        "registry_stored_bytes_peak": stored_bytes,
        "registration_seconds_each": register_seconds,
        "evaluation_seconds": evaluation_seconds,
        "evaluation_findings": len(evaluation.findings),
        "release_residual_tracemalloc_bytes": residual_before_repeat,
        "after_three_create_release_cycles_tracemalloc_bytes": tracemalloc.get_traced_memory()[0],
        "bytes_after_release": registry.stored_bytes,
    }


def main() -> None:
    gc.collect()
    tracemalloc.start()
    baseline_rss = _rss_bytes()
    baseline_allocation = tracemalloc.get_traced_memory()[0]
    result = run_before() if os.environ.get("ER_C3B_BENCHMARK_PHASE") == "before" else run_after()
    current_allocation, peak_allocation = tracemalloc.get_traced_memory()
    result.update(
        {
            "python": os.sys.version.split()[0],
            "platform": os.uname().sysname,
            "rss_unit": "bytes",
            "baseline_rss_bytes": baseline_rss,
            "peak_rss_bytes": _rss_bytes(),
            "baseline_tracemalloc_bytes": baseline_allocation,
            "current_tracemalloc_bytes": current_allocation,
            "peak_tracemalloc_bytes": peak_allocation,
        }
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
