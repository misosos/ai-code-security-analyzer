"""Internal TaintEvidence provenance and non-inference contract tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import (
    AssociationStatus,
    EvidenceState,
    TraceStatus,
    build_taint_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
RULE_FILE = RULES / "experimental" / "javascript-eval-taint.yml"
RULE_ID = "experimental.javascript-eval-taint"
COMMAND_RULE_FILE = RULES / "experimental" / "javascript-command-injection-taint.yml"
COMMAND_RULE_ID = "experimental.javascript-command-injection-taint"


def raw_result(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "check_id": RULE_ID,
        "path": "src/sample.ts",
        "start": {"line": 8, "col": 3},
        "end": {"line": 8, "col": 14},
        "extra": {
            "message": "synthetic source snippet is never retained",
            "severity": "ERROR",
            "metadata": {"cwe": "CWE-95"},
            "engine_kind": "OSS",
            "lines": "SYNTHETIC_PRIVATE_CODE_CANARY",
        },
    }
    value.update(updates)
    return value


def parse_and_build(tmp_path: Path, results: list[object], *, changes: dict[str, object] | None = None):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    document: dict[str, object] = {
        "version": "1.182.1",
        "engine_requested": "OSS",
        "results": results,
        "errors": [],
    }
    document.update(changes or {})
    internal = _parse_semgrep_json_internal(json.dumps(document).encode(), target)
    evidence = build_taint_evidence(
        internal.document,
        internal.result_findings,
        target,
        rules_file=RULE_FILE,
        trusted_rules_directory=RULES,
    )
    return internal, evidence


def test_observed_match_and_rule_declarations_are_separate(tmp_path: Path) -> None:
    internal, evidence = parse_and_build(tmp_path, [raw_result()])

    assert len(internal.parsed.findings) == len(evidence) == 1
    item = evidence[0]
    assert item.finding_id == internal.parsed.findings[0].finding_id
    assert item.association_status is AssociationStatus.EXACT
    assert item.rule_id == RULE_ID
    assert item.engine_name == "semgrep"
    assert item.engine_version == "1.182.1"
    assert item.analysis_scope == "per_file"
    assert item.matched_file == "src/sample.ts"
    assert (item.matched_start.line, item.matched_start.column) == (8, 3)
    assert (item.matched_end.line, item.matched_end.column) == (8, 14)
    assert item.match_status is EvidenceState.AVAILABLE
    assert item.source_patterns_declared == ("$REQ.query.code", "$REQ.body.code")
    assert item.source_location is None
    assert item.source_location_status is EvidenceState.UNKNOWN
    assert item.sink_patterns_declared == ("eval($CODE)",)
    assert item.sink_location is None
    assert item.sink_location_status is EvidenceState.UNKNOWN
    assert item.flow_trace_status is TraceStatus.ABSENT
    assert item.rules_file_id == "experimental/javascript-eval-taint.yml"
    assert item.rules_file_sha256
    assert "extra.lines" not in item.observed_json_fields


def test_multiple_rules_at_same_location_remain_separate(tmp_path: Path) -> None:
    second = raw_result(check_id="experimental.javascript-eval-taint-with-synthetic-sanitizer")
    _internal, evidence = parse_and_build(tmp_path, [raw_result(), second])

    assert len(evidence) == 2
    assert evidence[0].finding_id != evidence[1].finding_id
    assert {item.rule_id for item in evidence} == {
        RULE_ID,
        "experimental.javascript-eval-taint-with-synthetic-sanitizer",
    }
    assert evidence[1].sanitizer_patterns_declared == ("syntheticSafe($VALUE)",)
    assert evidence[1].sanitizer_match_status is EvidenceState.UNKNOWN


def test_duplicate_finding_identity_is_not_joined_ambiguously(tmp_path: Path) -> None:
    _internal, evidence = parse_and_build(tmp_path, [raw_result(), raw_result()])
    assert len(evidence) == 2
    assert all(item.finding_id is None for item in evidence)
    assert all(item.association_status is AssociationStatus.AMBIGUOUS for item in evidence)
    assert all("finding_association_ambiguous" in item.limitations for item in evidence)


def test_unknown_rule_configuration_does_not_claim_declarations(tmp_path: Path) -> None:
    changed_rules = tmp_path / "rules"
    (changed_rules / "experimental").mkdir(parents=True)
    changed_file = changed_rules / "experimental" / "javascript-eval-taint.yml"
    shutil.copyfile(RULE_FILE, changed_file)
    changed_file.write_text(changed_file.read_text() + "# changed after PoC\n")
    target = tmp_path / "target"
    target.mkdir()
    doc = {"version": "1.182.1", "engine_requested": "OSS", "results": [raw_result()], "errors": []}
    internal = _parse_semgrep_json_internal(json.dumps(doc).encode(), target)
    evidence = build_taint_evidence(
        internal.document,
        internal.result_findings,
        target,
        rules_file=changed_file,
        trusted_rules_directory=changed_rules,
    )

    assert len(evidence) == 1
    assert evidence[0].source_patterns_declared == ()
    assert evidence[0].sink_patterns_declared == ()
    assert evidence[0].source_declaration_status is EvidenceState.UNAVAILABLE
    assert evidence[0].rules_file_sha256
    assert evidence[0].finding_id is not None


def test_source_sink_and_trace_are_never_inferred_from_match(tmp_path: Path) -> None:
    _internal, evidence = parse_and_build(tmp_path, [raw_result()])
    item = evidence[0]
    assert item.source_location is None
    assert item.sink_location is None
    assert item.flow_trace_status is TraceStatus.ABSENT
    assert item.matched_start is not None
    assert item.matched_start != item.sink_location


def test_rule_registry_binds_command_rule_to_reviewed_path_hash_and_declarations(tmp_path: Path) -> None:
    from ai_code_security_analyzer.taint_evidence import _trusted_declaration

    sources, sinks, sanitizers, file_id, digest, status = _trusted_declaration(
        COMMAND_RULE_ID, COMMAND_RULE_FILE, RULES
    )
    assert status is EvidenceState.AVAILABLE
    assert file_id == "experimental/javascript-command-injection-taint.yml"
    assert digest == "abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783"
    assert sources == ("req.query.cmd", "req.body.cmd")
    assert len(sinks) == 4
    assert all("first argument focused" in pattern for pattern in sinks)
    assert any("named imports" in pattern for pattern in sinks)
    assert any("destructured require" in pattern for pattern in sinks)
    assert sanitizers == ()
    rule_text = COMMAND_RULE_FILE.read_text(encoding="utf-8")
    assert f"id: {COMMAND_RULE_ID}" in rule_text
    assert "pattern: req.query.cmd" in rule_text
    assert "pattern: req.body.cmd" in rule_text
    assert "focus-metavariable: $CMD" in rule_text
    assert "pattern-sanitizers:" not in rule_text

    # Same rule ID at another path and another rule ID at this path are denied.
    assert _trusted_declaration(COMMAND_RULE_ID, RULE_FILE, RULES)[-1] is EvidenceState.UNAVAILABLE
    assert _trusted_declaration(RULE_ID, COMMAND_RULE_FILE, RULES)[-1] is EvidenceState.UNAVAILABLE

    changed_root = tmp_path / "rules"
    (changed_root / "experimental").mkdir(parents=True)
    changed_file = changed_root / "experimental" / "javascript-command-injection-taint.yml"
    shutil.copyfile(COMMAND_RULE_FILE, changed_file)
    changed_file.write_bytes(changed_file.read_bytes() + b"# modified\n")
    changed = _trusted_declaration(COMMAND_RULE_ID, changed_file, changed_root)
    assert changed[-1] is EvidenceState.UNAVAILABLE
    assert changed[3] == "experimental/javascript-command-injection-taint.yml"
    assert changed[4] != digest


def test_command_rule_symlink_outside_trusted_directory_is_rejected(tmp_path: Path) -> None:
    from ai_code_security_analyzer.taint_evidence import _trusted_declaration

    trusted_root = tmp_path / "trusted"
    (trusted_root / "experimental").mkdir(parents=True)
    link = trusted_root / "experimental" / "javascript-command-injection-taint.yml"
    link.symlink_to(COMMAND_RULE_FILE)
    result = _trusted_declaration(COMMAND_RULE_ID, link, trusted_root)
    assert result[-1] is EvidenceState.UNAVAILABLE
    assert result[3] is None


def test_trace_shapes_are_not_retained_or_promoted_to_available(tmp_path: Path) -> None:
    nested_canary = "SYNTHETIC_TRACE_CODE_CANARY"
    _internal, unsupported = parse_and_build(
        tmp_path,
        [raw_result(dataflow_trace={"steps": [{"code": nested_canary}]})],
    )
    assert unsupported[0].flow_trace_status is TraceStatus.UNSUPPORTED
    assert nested_canary not in repr(unsupported)

    malformed_root = tmp_path / "other-target"
    malformed_root.mkdir()
    doc = {"version": "1.182.1", "engine_requested": "OSS", "results": [raw_result(dataflow_trace="not-a-trace")], "errors": []}
    internal = _parse_semgrep_json_internal(json.dumps(doc).encode(), malformed_root)
    malformed = build_taint_evidence(
        internal.document,
        internal.result_findings,
        malformed_root,
        rules_file=RULE_FILE,
        trusted_rules_directory=RULES,
    )
    assert malformed[0].flow_trace_status is TraceStatus.MALFORMED

    for index, empty_value in enumerate(([], {})):
        empty_root = tmp_path / f"empty-{index}"
        empty_root.mkdir()
        empty_doc = {
            "version": "1.182.1",
            "engine_requested": "OSS",
            "results": [raw_result(dataflow_trace=empty_value)],
            "errors": [],
        }
        empty_parsed = _parse_semgrep_json_internal(json.dumps(empty_doc).encode(), empty_root)
        empty_evidence = build_taint_evidence(
            empty_parsed.document,
            empty_parsed.result_findings,
            empty_root,
            rules_file=RULE_FILE,
            trusted_rules_directory=RULES,
        )
        assert empty_evidence[0].flow_trace_status is TraceStatus.EMPTY
        assert "trace_field_present_empty" in empty_evidence[0].limitations


def test_invalid_path_and_position_do_not_create_match_location(tmp_path: Path) -> None:
    _internal, invalid_path = parse_and_build(tmp_path, [raw_result(path="../outside.ts")])
    assert len(invalid_path) == 1
    assert invalid_path[0].matched_file is None
    assert invalid_path[0].match_status is EvidenceState.UNAVAILABLE
    assert invalid_path[0].finding_id is None

    other_target = tmp_path / "other"
    other_target.mkdir()
    raw = raw_result(end={"line": 7, "col": 2})
    doc = {"version": "1.182.1", "engine_requested": "OSS", "results": [raw], "errors": []}
    internal = _parse_semgrep_json_internal(json.dumps(doc).encode(), other_target)
    invalid_position = build_taint_evidence(
        internal.document,
        internal.result_findings,
        other_target,
        rules_file=RULE_FILE,
        trusted_rules_directory=RULES,
    )
    assert invalid_position[0].match_status is EvidenceState.MALFORMED
    assert invalid_position[0].matched_end is None


def test_wrong_finding_association_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    doc = {"version": "1.182.1", "engine_requested": "OSS", "results": [raw_result()], "errors": []}
    internal = _parse_semgrep_json_internal(json.dumps(doc).encode(), target)
    mismatched = internal.result_findings[0].model_copy(update={"rule_id": "other.rule"})
    evidence = build_taint_evidence(
        internal.document,
        (mismatched,),
        target,
        rules_file=RULE_FILE,
        trusted_rules_directory=RULES,
    )
    assert len(evidence) == 1
    assert evidence[0].finding_id is None
    assert evidence[0].association_status is AssociationStatus.AMBIGUOUS

    forged_id = internal.result_findings[0].model_copy(update={"finding_id": "forged"})
    evidence = build_taint_evidence(
        internal.document,
        (forged_id,),
        target,
        rules_file=RULE_FILE,
        trusted_rules_directory=RULES,
    )
    assert evidence[0].finding_id is None
    assert evidence[0].association_status is AssociationStatus.AMBIGUOUS


def test_sensitive_semgrep_fields_never_enter_taint_evidence(tmp_path: Path) -> None:
    canaries = ("SYNTHETIC_PRIVATE_CODE_CANARY", "SYNTHETIC_ERROR_CANARY", "SYNTHETIC_SECRET_CANARY")
    item = raw_result()
    item["extra"] = {
        "message": canaries[0],
        "lines": canaries[1],
        "severity": "ERROR",
        "metadata": {"cwe": "CWE-95"},
        "engine_kind": "OSS",
        "dataflow_trace": {"private": canaries[2]},
    }
    internal, evidence = parse_and_build(tmp_path, [item], changes={"errors": [{"message": canaries[1]}]})

    assert len(evidence) == 1
    assert all(secret not in repr(evidence) for secret in canaries)
    assert all(secret not in repr(internal.parsed) for secret in canaries)
    assert internal.parsed.findings[0].status.value == "unverified"
    assert internal.parsed.findings[0].confirmation is None


def test_baseline_rule_is_not_misclassified_as_taint(tmp_path: Path) -> None:
    item = raw_result(check_id="baseline.javascript-dynamic-eval")
    _internal, evidence = parse_and_build(tmp_path, [item])
    assert evidence == ()
