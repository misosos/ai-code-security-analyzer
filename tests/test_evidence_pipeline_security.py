"""Independent negative tests for the evidence consumer trust boundary.

Expected supported claims are fixed here from the documented policy. They are
not derived from the Gate or consumer under test.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from ai_code_security_analyzer.evidence_consumer import (
    EvidenceConsumerError,
    ValidatedEvidence,
    consume_evidence_summary,
)
from ai_code_security_analyzer.evidence_summary import (
    EvidenceSummary,
    build_evidence_summary,
)
from ai_code_security_analyzer.evidence_sufficiency import ClaimDecision, ClaimType
from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import build_taint_evidence


REPO_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_RULES = REPO_ROOT / "rules"
TAINT_RULE = TRUSTED_RULES / "experimental" / "javascript-eval-taint.yml"
RULE_ID = "experimental.javascript-eval-taint"
CANARY = "SYNTHETIC_PIPELINE_CANARY_7d5e"

# Independent policy oracle: only observed match, declared taint rule
# components, and the Semgrep match location are supported for this fixture.
EXPECTED_TAINT_SUPPORTED = frozenset(
    {
        ClaimType.MATCH_REPORTED,
        ClaimType.TAINT_RULE_MATCH_REPORTED,
        ClaimType.SOURCE_PATTERN_DECLARED,
        ClaimType.SINK_PATTERN_DECLARED,
        ClaimType.MATCH_LOCATION_OBSERVED,
    }
)
EXPECTED_PATTERN_SUPPORTED = frozenset({ClaimType.MATCH_REPORTED})
MUST_REMAIN_RESTRICTED = frozenset(
    {
        ClaimType.SOURCE_LOCATION_IDENTIFIED,
        ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED,
        ClaimType.FLOW_TRACE_AVAILABLE,
        ClaimType.SANITIZER_MATCH_OBSERVED,
        ClaimType.SANITIZER_EFFECTIVENESS_VERIFIED,
        ClaimType.VULNERABILITY_CONFIRMED,
    }
)


def _make_case(
    tmp_path: Path,
    *,
    line: int = 5,
    taint: bool = True,
    status: ScanStatus = ScanStatus.COMPLETED,
):
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    rule_id = RULE_ID if taint else "baseline.javascript-dynamic-eval"
    raw = {
        "version": "1.182.1",
        "engine_requested": "OSS",
        "results": [
            {
                "check_id": rule_id,
                "path": "src/synthetic.ts",
                "start": {"line": line, "col": 2},
                "end": {"line": line, "col": 8},
                "extra": {
                    "message": CANARY,
                    "severity": "ERROR",
                    "engine_kind": "OSS",
                    "lines": CANARY,
                    "secret_test_field": CANARY,
                },
            }
        ],
        "errors": [],
    }
    parsed = _parse_semgrep_json_internal(json.dumps(raw).encode(), target)
    finding = parsed.parsed.findings[0]
    evidence = (
        build_taint_evidence(
            parsed.document,
            parsed.result_findings,
            target,
            rules_file=TAINT_RULE,
            trusted_rules_directory=TRUSTED_RULES,
        )[0]
        if taint
        else None
    )
    scan = ScanResult(status, (finding,), (), 0, "1.182.1")
    kwargs = {
        "evidence": evidence,
        "scan_result": scan,
        "rules_file": TAINT_RULE if taint else None,
        "trusted_rules_directory": TRUSTED_RULES if taint else None,
    }
    summary = build_evidence_summary(finding, **kwargs)
    return target, finding, evidence, scan, summary, kwargs


def _consume(summary, finding, kwargs):
    return consume_evidence_summary(summary, finding, **kwargs)


def _as_untrusted_model_construct(summary: EvidenceSummary, **updates) -> EvidenceSummary:
    # Deliberately bypass Pydantic validation to model corrupted in-process data.
    values = summary.model_dump()
    values.update(updates)
    return EvidenceSummary.model_construct(**values)


def test_fixed_independent_expectations_for_taint_and_pattern(tmp_path: Path) -> None:
    _, finding, _, _, summary, kwargs = _make_case(tmp_path)
    result = _consume(summary, finding, kwargs)
    assert frozenset(result.allowed_claim_types) == EXPECTED_TAINT_SUPPORTED
    assert MUST_REMAIN_RESTRICTED.isdisjoint(result.allowed_claim_types)
    assert result.finding_verification_status is FindingStatus.UNVERIFIED

    _, pattern, _, _, pattern_summary, pattern_kwargs = _make_case(tmp_path / "pattern", taint=False)
    pattern_result = _consume(pattern_summary, pattern, pattern_kwargs)
    assert frozenset(pattern_result.allowed_claim_types) == EXPECTED_PATTERN_SUPPORTED
    assert ClaimType.TAINT_RULE_MATCH_REPORTED not in pattern_result.allowed_claim_types


@pytest.mark.parametrize(
    ("claim_type", "taint"),
    [
        (ClaimType.SOURCE_LOCATION_IDENTIFIED, True),
        (ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED, True),
        (ClaimType.FLOW_TRACE_AVAILABLE, True),
        (ClaimType.SANITIZER_MATCH_OBSERVED, True),
        (ClaimType.SANITIZER_EFFECTIVENESS_VERIFIED, True),
        (ClaimType.VULNERABILITY_CONFIRMED, True),
        (ClaimType.TAINT_RULE_MATCH_REPORTED, False),
    ],
)
def test_claim_promotion_matrix_is_rejected_without_partial_result(
    tmp_path: Path, claim_type: ClaimType, taint: bool
) -> None:
    _, finding, _, _, summary, kwargs = _make_case(tmp_path, taint=taint)
    claims = {
        item.claim_type: item
        for item in (*summary.supported_claims, *summary.restricted_claims)
    }
    claims[claim_type] = claims[claim_type].model_copy(
        update={"decision": ClaimDecision.SUPPORTED}
    )
    promoted = _as_untrusted_model_construct(
        summary,
        supported_claims=tuple(
            claims[kind] for kind in ClaimType if claims[kind].decision is ClaimDecision.SUPPORTED
        ),
        restricted_claims=tuple(
            claims[kind] for kind in ClaimType if claims[kind].decision is not ClaimDecision.SUPPORTED
        ),
    )
    with pytest.raises(EvidenceConsumerError) as error:
        _consume(promoted, finding, kwargs)
    assert str(error.value) == "evidence_consumer_rejected"
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.confirmation is None


@pytest.mark.parametrize(
    ("status", "forged_status"),
    [
        (ScanStatus.PARTIAL, ScanStatus.COMPLETED),
        (ScanStatus.COMPLETED, ScanStatus.PARTIAL),
    ],
)
def test_scan_completion_status_cannot_be_changed_after_summary(
    tmp_path: Path, status: ScanStatus, forged_status: ScanStatus
) -> None:
    _, finding, evidence, scan, summary, kwargs = _make_case(tmp_path, status=status)
    forged_summary = _as_untrusted_model_construct(summary, scan_status=forged_status)
    with pytest.raises(EvidenceConsumerError):
        _consume(forged_summary, finding, kwargs)


def test_unknown_scan_state_cannot_be_rewritten_as_completed(tmp_path: Path) -> None:
    _, finding, evidence, _, _, _ = _make_case(tmp_path)
    summary = build_evidence_summary(finding, evidence=evidence, scan_result=None)
    forged = _as_untrusted_model_construct(summary, scan_status=ScanStatus.COMPLETED)
    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(forged, finding, evidence=evidence, scan_result=None)


@pytest.mark.parametrize(
    ("status", "exit_code", "issues", "expected"),
    [
        (
            ScanStatus.PARTIAL,
            0,
            ("synthetic_skipped_paths",),
            frozenset(
                {
                    ClaimType.MATCH_REPORTED,
                    ClaimType.SOURCE_PATTERN_DECLARED,
                    ClaimType.SINK_PATTERN_DECLARED,
                    ClaimType.MATCH_LOCATION_OBSERVED,
                }
            ),
        ),
        (ScanStatus.COMPLETED, 1, (), frozenset()),
        (ScanStatus.COMPLETED, 0, ("synthetic_issue",), frozenset()),
        (ScanStatus.EXECUTION_FAILED, None, ("synthetic_execution_failure",), frozenset()),
        (ScanStatus.TIMED_OUT, None, ("synthetic_timeout",), frozenset()),
        (ScanStatus.NOT_INSTALLED, None, ("synthetic_missing_semgrep",), frozenset()),
        (ScanStatus.OUTPUT_LIMIT_EXCEEDED, None, ("synthetic_limit",), frozenset()),
        (ScanStatus.INVALID_JSON, 0, ("synthetic_invalid_json",), frozenset()),
    ],
)
def test_scan_status_and_metadata_are_not_upgraded(
    tmp_path: Path,
    status: ScanStatus,
    exit_code: int | None,
    issues: tuple[str, ...],
    expected: frozenset[ClaimType],
) -> None:
    _, finding, evidence, scan, _, _ = _make_case(tmp_path)
    altered_scan = replace(scan, status=status, exit_code=exit_code, issues=issues)
    kwargs = {
        "evidence": evidence,
        "scan_result": altered_scan,
        "rules_file": TAINT_RULE,
        "trusted_rules_directory": TRUSTED_RULES,
    }
    summary = build_evidence_summary(finding, **kwargs)
    result = _consume(summary, finding, kwargs)
    assert frozenset(result.allowed_claim_types) == expected
    assert result.scan_status is status
    if status is ScanStatus.PARTIAL:
        assert ClaimType.TAINT_RULE_MATCH_REPORTED not in result.allowed_claim_types


@pytest.mark.parametrize(
    ("scan_update", "expected"),
    [
        ({"semgrep_version": None}, frozenset()),
        ({"semgrep_version": "1.182"}, frozenset()),
        ({"exit_code": None}, frozenset()),
    ],
)
def test_missing_or_malformed_scan_metadata_never_supports_match(
    tmp_path: Path, scan_update: dict[str, object], expected: frozenset[ClaimType]
) -> None:
    _, finding, evidence, scan, _, _ = _make_case(tmp_path)
    changed_scan = replace(scan, **scan_update)
    kwargs = {"evidence": evidence, "scan_result": changed_scan}
    summary = build_evidence_summary(finding, **kwargs)
    result = _consume(summary, finding, kwargs)
    assert frozenset(result.allowed_claim_types) == expected


def test_unknown_scan_status_is_not_promoted_to_completed(tmp_path: Path) -> None:
    _, finding, evidence, scan, _, _ = _make_case(tmp_path)
    malformed_scan = replace(scan, status="future_status")  # type: ignore[arg-type]
    kwargs = {"evidence": evidence, "scan_result": malformed_scan}
    summary = build_evidence_summary(finding, **kwargs)
    result = _consume(summary, finding, kwargs)
    assert result.scan_status is None
    assert result.allowed_claims == ()


def test_other_finding_same_rule_and_other_taint_evidence_are_rejected(tmp_path: Path) -> None:
    _, finding_a, evidence_a, scan_a, summary_a, kwargs_a = _make_case(tmp_path / "a")
    _, finding_b, evidence_b, scan_b, _, _ = _make_case(tmp_path / "b", line=12)

    with pytest.raises(EvidenceConsumerError):
        _consume(summary_a, finding_b, {**kwargs_a, "scan_result": scan_b, "evidence": evidence_b})
    with pytest.raises(EvidenceConsumerError):
        _consume(summary_a, finding_a, {**kwargs_a, "scan_result": scan_b})
    with pytest.raises(EvidenceConsumerError):
        _consume(summary_a, finding_a, {**kwargs_a, "evidence": evidence_b})

    duplicate_scan = replace(scan_a, findings=(finding_a, finding_a))
    duplicate_summary = build_evidence_summary(
        finding_a,
        evidence=evidence_a,
        scan_result=duplicate_scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=TRUSTED_RULES,
    )
    with pytest.raises(EvidenceConsumerError):
        _consume(
            duplicate_summary,
            finding_a,
            {**kwargs_a, "scan_result": duplicate_scan},
        )


def test_same_location_different_rules_keep_evidence_separate(tmp_path: Path) -> None:
    target, taint_finding, taint_evidence, _, _, _ = _make_case(tmp_path)
    raw = {
        "version": "1.182.1",
        "engine_requested": "OSS",
        "results": [
            {
                "check_id": "baseline.javascript-dynamic-eval",
                "path": taint_finding.file_path,
                "start": {"line": taint_finding.line_number, "col": 2},
                "end": {"line": taint_finding.line_number, "col": 8},
                "extra": {"message": CANARY, "severity": "ERROR", "engine_kind": "OSS"},
            }
        ],
        "errors": [],
    }
    parsed = _parse_semgrep_json_internal(json.dumps(raw).encode(), target)
    pattern_finding = parsed.parsed.findings[0]
    scan = ScanResult(
        ScanStatus.COMPLETED,
        (taint_finding, pattern_finding),
        (),
        0,
        "1.182.1",
    )
    taint_summary = build_evidence_summary(
        taint_finding,
        evidence=taint_evidence,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=TRUSTED_RULES,
    )
    pattern_summary = build_evidence_summary(pattern_finding, scan_result=scan)

    taint_result = consume_evidence_summary(
        taint_summary,
        taint_finding,
        evidence=taint_evidence,
        scan_result=scan,
        rules_file=TAINT_RULE,
        trusted_rules_directory=TRUSTED_RULES,
    )
    pattern_result = consume_evidence_summary(pattern_summary, pattern_finding, scan_result=scan)
    assert taint_result.finding_kind.value == "taint"
    assert pattern_result.finding_kind.value == "pattern"
    assert pattern_finding.finding_id != taint_finding.finding_id

    with pytest.raises(EvidenceConsumerError):
        consume_evidence_summary(
            pattern_summary,
            pattern_finding,
            evidence=taint_evidence,
            scan_result=scan,
            rules_file=TAINT_RULE,
            trusted_rules_directory=TRUSTED_RULES,
        )


def test_same_finding_id_with_changed_finding_properties_is_detected(tmp_path: Path) -> None:
    _, finding, evidence, scan, summary, kwargs = _make_case(tmp_path)
    changed = finding.model_copy(update={"title": "synthetic changed title"})
    with pytest.raises(EvidenceConsumerError):
        _consume(summary, changed, kwargs)

    # If both in-memory objects are forged consistently, the current contracts
    # cannot attest them against the original Semgrep process output.
    forged_scan = replace(scan, findings=(changed,))
    forged_kwargs = {**kwargs, "scan_result": forged_scan}
    forged_summary = build_evidence_summary(changed, **forged_kwargs)
    accepted = _consume(forged_summary, changed, forged_kwargs)
    assert accepted.finding_id == finding.finding_id
    assert accepted.finding_verification_status is FindingStatus.UNVERIFIED


def test_structurally_identical_independent_scans_are_not_distinguishable(tmp_path: Path) -> None:
    _, finding, evidence, scan, summary, kwargs = _make_case(tmp_path)
    second_scan = replace(scan, findings=tuple(item.model_copy() for item in scan.findings))
    assert second_scan is not scan
    result = _consume(summary, finding, {**kwargs, "scan_result": second_scan})
    assert frozenset(result.allowed_claim_types) == EXPECTED_TAINT_SUPPORTED


def test_rule_change_then_exact_restore_revalidates_same_digest(tmp_path: Path) -> None:
    _, finding, evidence, _scan, _summary, _ = _make_case(tmp_path)
    trusted_root = tmp_path / "trusted-rules"
    rule_copy = trusted_root / "experimental" / TAINT_RULE.name
    rule_copy.parent.mkdir(parents=True)
    original = TAINT_RULE.read_bytes()
    shutil.copyfile(TAINT_RULE, rule_copy)
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    kwargs = {
        "evidence": evidence,
        "scan_result": scan,
        "rules_file": rule_copy,
        "trusted_rules_directory": trusted_root,
    }
    summary = build_evidence_summary(finding, **kwargs)

    rule_copy.write_bytes(original + b"\n# synthetic temporary modification\n")
    with pytest.raises(EvidenceConsumerError):
        _consume(summary, finding, kwargs)
    rule_copy.write_bytes(original)
    result = _consume(summary, finding, kwargs)
    assert frozenset(result.allowed_claim_types) == EXPECTED_TAINT_SUPPORTED


def test_rule_path_replaced_by_symlink_outside_trusted_root_is_rejected(tmp_path: Path) -> None:
    _, finding, evidence, _, _, _ = _make_case(tmp_path)
    trusted_root = tmp_path / "trusted-rules"
    rule_copy = trusted_root / "experimental" / TAINT_RULE.name
    rule_copy.parent.mkdir(parents=True)
    shutil.copyfile(TAINT_RULE, rule_copy)
    scan = ScanResult(ScanStatus.COMPLETED, (finding,), (), 0, "1.182.1")
    kwargs = {
        "evidence": evidence,
        "scan_result": scan,
        "rules_file": rule_copy,
        "trusted_rules_directory": trusted_root,
    }
    summary = build_evidence_summary(finding, **kwargs)

    outside = tmp_path / "outside-rule.yml"
    shutil.copyfile(TAINT_RULE, outside)
    rule_copy.unlink()
    rule_copy.symlink_to(outside)
    with pytest.raises(EvidenceConsumerError):
        _consume(summary, finding, kwargs)


def test_consumer_output_and_error_do_not_disclose_synthetic_raw_fields(tmp_path: Path) -> None:
    _, finding, evidence, scan, summary, kwargs = _make_case(tmp_path)
    result = _consume(summary, finding, kwargs)
    assert CANARY not in summary.model_dump_json()
    assert CANARY not in result.model_dump_json()
    assert "src/synthetic.ts" not in result.model_dump_json()

    altered = _as_untrusted_model_construct(summary, finding_id="invalid-id-canary-" + CANARY)
    with pytest.raises(EvidenceConsumerError) as error:
        _consume(altered, finding, kwargs)
    assert CANARY not in str(error.value)
    assert "src/synthetic.ts" not in repr(error.value)


@pytest.mark.parametrize(
    "mutation",
    [
        {"finding_id": "semgrep:" + "x" * 24},
        {"rule_id": "../untrusted"},
        {"engine_version": "1.182.1\n" + CANARY},
        {"rule_id": "x" * 4097},
        {"association_status": "future_association"},
    ],
)
def test_malformed_summary_shapes_fail_closed_with_fixed_error(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    _, finding, _, _, summary, kwargs = _make_case(tmp_path)
    malformed = _as_untrusted_model_construct(summary, **mutation)
    with pytest.raises(EvidenceConsumerError) as error:
        _consume(malformed, finding, kwargs)
    assert str(error.value) == "evidence_consumer_rejected"
    assert CANARY not in repr(error.value)


def test_wrong_object_type_fails_closed_without_raw_diagnostic(tmp_path: Path) -> None:
    _, finding, _, _, _, kwargs = _make_case(tmp_path)
    with pytest.raises(EvidenceConsumerError) as error:
        consume_evidence_summary(object(), finding, **kwargs)  # type: ignore[arg-type]
    assert str(error.value) == "evidence_consumer_rejected"


def test_deserialization_and_pydantic_low_level_bypass_are_not_attestations(tmp_path: Path) -> None:
    _, finding, _, _, summary, _ = _make_case(tmp_path)
    decoded = EvidenceSummary.model_validate_json(summary.model_dump_json())
    with pytest.raises(TypeError):
        consume_evidence_summary(decoded, finding)  # type: ignore[call-arg]

    with pytest.raises(TypeError, match="use_consume_evidence_summary"):
        ValidatedEvidence.model_validate(
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "finding_kind": "taint",
                "allowed_claims": [],
                "restricted_claims": [],
            }
        )

    forged = ValidatedEvidence.model_construct(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        finding_kind="pattern",
        allowed_claims=(),
        restricted_claims=(),
    )
    # Pydantic's explicit low-level constructor can bypass __init__. This test
    # records the limitation: only function-returned objects are consumable.
    assert forged.validation_status.value == "validated"
    assert forged.allowed_claims == ()


def test_source_tree_changes_are_outside_consumer_inputs(tmp_path: Path) -> None:
    target, finding, evidence, scan, summary, kwargs = _make_case(tmp_path)
    source = target / "src" / "synthetic.ts"
    source.parent.mkdir(parents=True)
    source.write_text("const input = 'before'; eval(input);\n")
    first = _consume(summary, finding, kwargs)
    source.write_text("const input = 'after'; eval(input);\n")
    second = _consume(summary, finding, kwargs)
    assert first.model_dump() == second.model_dump()
