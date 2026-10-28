"""Offline validation tests for the evaluation-only minimal response contract."""

from __future__ import annotations

import json

from ai_code_security_analyzer.code_context import extract_code_context
from ai_code_security_analyzer.evidence_candidates import build_evidence_candidates
from ai_code_security_analyzer.minimal_evidence import (
    minimal_evidence_response_schema,
    validate_minimal_evidence_response,
)
from ai_code_security_analyzer.models import Finding, FindingStatus, Severity


def _case(tmp_path):
    (tmp_path / "sample.ts").write_text(
        "const expression = query.expression;\nconst result = eval(expression);\n",
        encoding="utf-8",
    )
    finding = Finding(
        finding_id="synthetic:minimal", rule_id="synthetic.eval",
        title="Synthetic candidate", description="Synthetic static-analysis candidate",
        severity=Severity.HIGH, source_tool="semgrep", file_path="sample.ts",
        line_number=2, evidence="Synthetic fixture only",
    )
    context = extract_code_context(tmp_path, finding)
    bundle = build_evidence_candidates(finding, context)
    return finding, context, bundle


def _response(assessment="likely_true_positive", selected=None, reason=None, **extra):
    value = {
        "assessment": assessment,
        "selected_candidate_ids": selected or [],
        "missing_context_reason": reason,
        **extra,
    }
    return json.dumps(value)


def test_minimal_schema_requires_only_three_fields_and_forbids_extras():
    schema = minimal_evidence_response_schema()
    assert set(schema["required"]) == {
        "assessment", "selected_candidate_ids", "missing_context_reason"
    }
    assert schema["additionalProperties"] is False


def test_valid_candidate_selection_is_structural_and_not_semantic(tmp_path):
    finding, context, bundle = _case(tmp_path)
    before = finding.model_dump(mode="json")
    candidate = next(item for item in bundle.candidates if item.candidate_kind.value == "call_expression")
    result = validate_minimal_evidence_response(
        _response(selected=[candidate.candidate_id]), finding, context, bundle
    )
    assert result.review is not None
    assert result.review.selected_candidate_ids == (candidate.candidate_id,)
    assert result.review.candidate_ids_structurally_valid is True
    assert result.review.semantic_claims_verified is False
    assert finding.model_dump(mode="json") == before
    assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None


def test_inconclusive_requires_specific_reason_and_may_select_no_candidates(tmp_path):
    finding, context, bundle = _case(tmp_path)
    good = validate_minimal_evidence_response(
        _response("inconclusive", reason="The caller and input origin are outside this snippet."),
        finding, context, bundle,
    )
    assert good.review is not None
    assert good.review.selected_candidate_ids == ()
    for reason in (None, "", "   "):
        invalid = validate_minimal_evidence_response(
            _response("inconclusive", reason=reason), finding, context, bundle
        )
        assert invalid.code in {"review_contract_failed", "schema_validation_failed"}


def test_directional_assessment_requires_candidate_and_allowed_assessment(tmp_path):
    finding, context, bundle = _case(tmp_path)
    no_candidate = validate_minimal_evidence_response(
        _response("likely_true_positive"), finding, context, bundle
    )
    assert no_candidate.code == "review_contract_failed"
    invalid_assessment = validate_minimal_evidence_response(
        _response("confirmed", reason="No."), finding, context, bundle
    )
    assert invalid_assessment.code == "schema_validation_failed"

    location_only = next(item for item in bundle.candidates
                         if item.candidate_kind.value == "finding_location")
    irrelevant = validate_minimal_evidence_response(
        _response("likely_true_positive", selected=[location_only.candidate_id]),
        finding, context, bundle,
    )
    assert irrelevant.code == "candidate_kind_not_relevant"


def test_likely_false_positive_requires_a_supplied_condition_candidate(tmp_path):
    (tmp_path / "guarded.ts").write_text(
        "const expression = query.expression;\n"
        "if (isAllowed(expression)) {\n"
        "  const result = eval(expression);\n"
        "}\n",
        encoding="utf-8",
    )
    finding = Finding(
        finding_id="synthetic:guarded", rule_id="synthetic.eval",
        title="Synthetic candidate", description="Synthetic static-analysis candidate",
        severity=Severity.HIGH, source_tool="semgrep", file_path="guarded.ts",
        line_number=3, evidence="Synthetic fixture only",
    )
    context = extract_code_context(tmp_path, finding)
    bundle = build_evidence_candidates(finding, context)
    guard = next(item for item in bundle.candidates
                 if item.candidate_kind.value == "conditional_expression")
    accepted = validate_minimal_evidence_response(
        _response("likely_false_positive", selected=[guard.candidate_id]),
        finding, context, bundle,
    )
    assert accepted.review is not None
    call = next(item for item in bundle.candidates if item.candidate_kind.value == "call_expression")
    rejected = validate_minimal_evidence_response(
        _response("likely_false_positive", selected=[call.candidate_id]),
        finding, context, bundle,
    )
    assert rejected.code == "candidate_kind_not_relevant"


def test_unknown_duplicate_foreign_and_tampered_candidate_references_rejected(tmp_path):
    finding, context, bundle = _case(tmp_path)
    candidate = bundle.candidates[0]
    unknown = validate_minimal_evidence_response(
        _response(selected=["ec1_" + "0" * 64]), finding, context, bundle
    )
    assert unknown.code == "candidate_reference_invalid"
    duplicate = validate_minimal_evidence_response(
        _response(selected=[candidate.candidate_id, candidate.candidate_id]), finding, context, bundle
    )
    assert duplicate.code == "candidate_reference_invalid"

    other = finding.model_copy(update={"finding_id": "synthetic:other"})
    foreign = validate_minimal_evidence_response(
        _response(selected=[candidate.candidate_id]), other, context, bundle
    )
    assert foreign.code == "candidate_bundle_invalid"

    changed_candidate = candidate.model_copy(update={"candidate_id": "ec1_" + "a" * 64})
    changed_bundle = bundle.model_copy(update={
        "candidates": (changed_candidate, *bundle.candidates[1:]),
    })
    tampered = validate_minimal_evidence_response(
        _response(selected=[changed_candidate.candidate_id]), finding, context, changed_bundle
    )
    assert tampered.code == "candidate_bundle_invalid"


def test_extra_fields_sensitive_text_and_invalid_json_fail_closed(tmp_path):
    finding, context, bundle = _case(tmp_path)
    candidate = bundle.candidates[0]
    extra = validate_minimal_evidence_response(
        _response(selected=[candidate.candidate_id], confirmation="confirmed"),
        finding, context, bundle,
    )
    assert extra.code == "unexpected_response_field"
    sensitive = validate_minimal_evidence_response(
        _response("inconclusive", reason="token=ghp_" + "A" * 30), finding, context, bundle
    )
    assert sensitive.code == "unsafe_response_text"
    broken = validate_minimal_evidence_response("{", finding, context, bundle)
    assert broken.code == "invalid_json"


def test_response_cannot_be_converted_into_public_ai_review_or_change_finding(tmp_path):
    finding, context, bundle = _case(tmp_path)
    candidate = next(item for item in bundle.candidates if item.candidate_kind.value == "call_expression")
    result = validate_minimal_evidence_response(
        _response(selected=[candidate.candidate_id]), finding, context, bundle
    )
    assert result.review is not None
    assert not hasattr(result.review, "summary")
    assert not hasattr(result.review, "confirmation")
    assert finding.status is FindingStatus.UNVERIFIED and finding.confirmation is None


def test_partial_context_bundle_cannot_be_reused_for_minimal_review(tmp_path):
    from ai_code_security_analyzer.code_context import ContextStatus

    finding, context, bundle = _case(tmp_path)
    for status, redacted, truncated in (
        (ContextStatus.REDACTED, True, False),
        (ContextStatus.TRUNCATED, False, True),
        (ContextStatus.UNAVAILABLE, False, False),
    ):
        changed_metadata = context.metadata.model_copy(update={
            "status": status, "redacted": redacted, "truncated": truncated,
        })
        changed = type(context)(changed_metadata, context.lines)
        result = validate_minimal_evidence_response(
            _response("inconclusive", reason="The provided code is incomplete."),
            finding, changed, bundle,
        )
        assert result.review is None
        assert result.code == "candidate_bundle_invalid"
