"""Required Semgrep 1.182.1 OSS taint PoC on synthetic fixtures only."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import Counter
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus, Severity
from ai_code_security_analyzer.evidence_sufficiency import (
    ClaimDecision,
    ClaimType,
    evaluate_all_claims,
)
from ai_code_security_analyzer.evidence_summary import (
    FindingKind,
    RuleDeclarationStatus,
    SummaryAssociationStatus,
    build_evidence_summary,
    validate_evidence_summary,
)
from ai_code_security_analyzer.evidence_consumer import EvidenceConsumerError, consume_evidence_summary
from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.semgrep_adapter import (
    MAX_OUTPUT_BYTES,
    SCAN_TIMEOUT_SECONDS,
    ScanStatus,
    SemgrepAdapter,
    _run_process,
)
from ai_code_security_analyzer.semgrep_parser import parse_semgrep_json


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "semgrep_taint"
TRUSTED_RULES = ROOT / "rules"
TAINT_RULE = TRUSTED_RULES / "experimental" / "javascript-eval-taint.yml"
BASELINE_RULE = TRUSTED_RULES / "security-baseline.yml"
REQUIRED_VERSION = "1.182.1"
CANARY = "SYNTHETIC_TAINT_CANARY_ONLY"

# Expected sink lines for a source-to-sink relation within the OSS PoC scope.
EXPECTED_PLAIN_TAINT = {
    "A_direct.js": 2,
    "B_assignment.js": 3,
    "C_multistep.ts": 5,
    "F_unknown_sanitizer.ts": 3,
    "G_modeled_sanitizer.js": 3,
    "H_partial_condition.js": 4,
    "K_nested_conditions.ts": 8,
}
EXPECTED_MODELED_SANITIZER = {
    "A_direct.js": 2,
    "B_assignment.js": 3,
    "C_multistep.ts": 5,
    "F_unknown_sanitizer.ts": 3,
    "H_partial_condition.js": 4,
    "K_nested_conditions.ts": 8,
}
EXPECTED_BASELINE = {
    "A_direct.js": 2,
    "B_assignment.js": 3,
    "C_multistep.ts": 5,
    "D_constant.js": 3,
    "E_unrelated.js": 4,
    "F_unknown_sanitizer.ts": 3,
    "G_modeled_sanitizer.js": 3,
    "H_partial_condition.js": 4,
    "I_function_boundary.js": 6,
    "J_split_sink.js": 2,
    "K_nested_conditions.ts": 8,
}


def _require_semgrep() -> str:
    executable = shutil.which("semgrep")
    if executable is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    with tempfile.TemporaryDirectory(prefix="semgrep-version-home-") as home_value:
        home = Path(home_value)
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        result = _run_process([executable, "--version"], ROOT, env, 10)
    version = result.stdout.decode("utf-8", errors="replace").strip()
    if result.exit_code != 0 or version != REQUIRED_VERSION:
        pytest.fail("unexpected_semgrep_version")
    return executable


def _copy_fixtures(target: Path) -> None:
    target.mkdir()
    for source in FIXTURES.iterdir():
        if source.is_file():
            shutil.copyfile(source, target / source.name)


def _raw_taint_json(
    executable: str, target: Path, *, dataflow_traces: bool = False
) -> dict[str, object]:
    # Mirror adapter process isolation and bounded output for temporary raw JSON
    # inspection. The parsed object is never printed or persisted.
    with tempfile.TemporaryDirectory(prefix="semgrep-taint-home-") as home_value:
        home = Path(home_value)
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        args = [
            executable, "scan", "--json", "--metrics=off", "--disable-version-check",
            "--oss-only", "--no-autofix", "--config", TAINT_RULE.name, "--", str(target),
        ]
        if dataflow_traces:
            args.insert(args.index("--"), "--dataflow-traces")
        process = _run_process(args, TAINT_RULE.parent, env, SCAN_TIMEOUT_SECONDS)
    if process.exit_code != 0 or len(process.stdout) > MAX_OUTPUT_BYTES:
        pytest.fail("taint_semgrep_execution_failed")
    try:
        value = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pytest.fail("taint_semgrep_json_invalid")
    if not isinstance(value, dict):
        pytest.fail("taint_semgrep_json_invalid")
    return value


def _raw_taint_sarif(
    executable: str, target: Path, *, dataflow_traces: bool = False
) -> dict[str, object]:
    """Run bounded local SARIF evaluation; callers must not persist or print it."""
    with tempfile.TemporaryDirectory(prefix="semgrep-taint-sarif-home-") as home_value:
        home = Path(home_value)
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        args = [
            executable, "scan", "--sarif", "--metrics=off", "--disable-version-check",
            "--oss-only", "--no-autofix", "--config", TAINT_RULE.name,
        ]
        if dataflow_traces:
            args.append("--dataflow-traces")
        args.extend(["--", str(target)])
        process = _run_process(args, TAINT_RULE.parent, env, SCAN_TIMEOUT_SECONDS)
    if process.exit_code != 0 or len(process.stdout) > MAX_OUTPUT_BYTES:
        pytest.fail("taint_semgrep_sarif_execution_failed")
    try:
        value = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pytest.fail("taint_semgrep_sarif_invalid")
    if not isinstance(value, dict):
        pytest.fail("taint_semgrep_sarif_invalid")
    return value


def _sarif_result_signatures(document: dict[str, object], target: Path) -> tuple[Counter, Counter]:
    """Return validated match signatures and codeFlows presence, without text."""
    signatures: Counter = Counter()
    flow_states: Counter = Counter()
    runs = document.get("runs")
    if not isinstance(runs, list):
        return signatures, flow_states
    root = target.resolve()
    for run in runs:
        results = run.get("results") if isinstance(run, dict) else None
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            flows = result.get("codeFlows", "__absent__")
            if flows == "__absent__":
                flow_states["absent"] += 1
            elif isinstance(flows, list):
                flow_states["empty" if not flows else "present"] += 1
            else:
                flow_states["malformed"] += 1

            locations = result.get("locations")
            if not isinstance(locations, list) or len(locations) != 1:
                continue
            location = locations[0]
            physical = location.get("physicalLocation") if isinstance(location, dict) else None
            artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
            region = physical.get("region") if isinstance(physical, dict) else None
            uri = artifact.get("uri") if isinstance(artifact, dict) else None
            if not isinstance(uri, str) or not uri or "://" in uri or uri.startswith(("file:", "data:")):
                continue
            try:
                artifact_path = Path(uri)
                if not artifact_path.is_absolute() or ".." in artifact_path.parts:
                    continue
                relative = artifact_path.resolve().relative_to(root).as_posix()
            except (OSError, ValueError, RuntimeError):
                continue
            if not isinstance(region, dict):
                continue
            coordinates = tuple(region.get(key) for key in ("startLine", "startColumn", "endLine", "endColumn"))
            if not all(type(value) is int and value > 0 for value in coordinates):
                continue
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id:
                continue
            signatures[(rule_id, relative, *coordinates)] += 1
    return signatures, flow_states


def _json_result_signatures(document: dict[str, object], target: Path) -> Counter:
    signatures: Counter = Counter()
    results = document.get("results")
    if not isinstance(results, list):
        return signatures
    root = target.resolve()
    for result in results:
        if not isinstance(result, dict):
            continue
        raw_path = result.get("path")
        if not isinstance(raw_path, str) or not raw_path or "://" in raw_path:
            continue
        try:
            raw = Path(raw_path)
            if raw.is_absolute():
                relative = raw.resolve().relative_to(root).as_posix()
            else:
                relative = (root / raw).resolve().relative_to(root).as_posix()
        except (OSError, ValueError, RuntimeError):
            continue
        start = result.get("start")
        end = result.get("end")
        if not isinstance(start, dict) or not isinstance(end, dict):
            continue
        coordinates = (start.get("line"), start.get("col"), end.get("line"), end.get("col"))
        if not all(type(value) is int and value > 0 for value in coordinates):
            continue
        rule_id = result.get("check_id")
        if isinstance(rule_id, str) and rule_id:
            signatures[(rule_id, relative, *coordinates)] += 1
    return signatures


def test_sarif_codeflow_field_presence_is_not_conflated() -> None:
    # Synthetic shape checks only; these do not claim Semgrep emits these forms.
    def state(result: dict[str, object]) -> Counter:
        document = {"runs": [{"results": [result]}]}
        return _sarif_result_signatures(document, Path.cwd())[1]

    assert state({}) == Counter({"absent": 1})
    assert state({"codeFlows": []}) == Counter({"empty": 1})
    assert state({"codeFlows": [{"threadFlows": []}]}) == Counter({"present": 1})
    assert state({"codeFlows": {"unexpected": True}}) == Counter({"malformed": 1})


def test_oss_sarif_taint_results_match_json_without_dataflow_trace(tmp_path: Path) -> None:
    executable = _require_semgrep()
    target = tmp_path / "synthetic-target"
    _copy_fixtures(target)

    json_document = _raw_taint_json(executable, target)
    sarif_document = _raw_taint_sarif(executable, target)
    trace_document = _raw_taint_sarif(executable, target, dataflow_traces=True)

    json_signatures = _json_result_signatures(json_document, target)
    findings = parse_semgrep_json(json.dumps(json_document).encode(), target).findings
    finding_signatures = Counter(
        (finding.rule_id, finding.file_path, finding.line_number)
        for finding in findings
    )
    assert json_document.get("version") == REQUIRED_VERSION
    assert json_document.get("engine_requested") == "OSS"
    assert len(json_signatures) == len(findings) == 13
    assert Counter((rule, path, line) for rule, path, line, *_ in json_signatures.elements()) == finding_signatures

    for document in (sarif_document, trace_document):
        assert document.get("version") == "2.1.0"
        runs = document.get("runs")
        assert isinstance(runs, list) and len(runs) == 1
        run = runs[0]
        assert isinstance(run, dict)
        tool = run.get("tool")
        assert isinstance(tool, dict) and isinstance(tool.get("driver"), dict)
        assert tool["driver"].get("name") == "Semgrep OSS"
        results = run.get("results")
        assert isinstance(results, list) and len(results) == 13
        signatures, flow_states = _sarif_result_signatures(document, target)
        assert signatures == json_signatures
        assert len(signatures) == 13
        assert all(count == 1 for count in signatures.values())
        assert all(not Path(signature[1]).is_absolute() for signature in signatures)
        assert CANARY not in repr(signatures)
        assert flow_states == Counter({"absent": 13})
        # No codeFlows means no observed threadFlows or threadFlowLocations.
        assert all("codeFlows" not in result for result in results)

    plain_signatures, _ = _sarif_result_signatures(sarif_document, target)
    trace_signatures, _ = _sarif_result_signatures(trace_document, target)
    assert plain_signatures == trace_signatures
    # Both outputs are held only in memory and are never returned as public data.
    assert all(finding.status is FindingStatus.UNVERIFIED for finding in findings)
    assert all(finding.confirmation is None for finding in findings)


def _finding_locations(result) -> dict[tuple[str, str], tuple[int, str, str]]:
    return {
        (finding.file_path, finding.rule_id): (
            finding.line_number,
            finding.severity.value,
            finding.cwe or "",
        )
        for finding in result.findings
    }


def test_oss_taint_flows_baseline_difference_sanitizer_and_json_evidence(tmp_path: Path) -> None:
    executable = _require_semgrep()
    target = tmp_path / "synthetic-target"
    _copy_fixtures(target)

    adapter = SemgrepAdapter(TRUSTED_RULES)
    taint_output = adapter._scan_with_evidence(target, TAINT_RULE)
    taint = taint_output.result
    baseline_output = adapter._scan_with_evidence(target, BASELINE_RULE)
    baseline = baseline_output.result
    assert taint.status is baseline.status is ScanStatus.COMPLETED
    assert taint.semgrep_version == baseline.semgrep_version == REQUIRED_VERSION
    assert taint.issues == baseline.issues == ()
    assert len(taint_output.taint_evidence) == len(taint.findings)
    findings_by_id = {finding.finding_id: finding for finding in taint.findings}
    assert all(item.finding_id in findings_by_id for item in taint_output.taint_evidence)
    assert all(item.flow_trace_status.value == "absent" for item in taint_output.taint_evidence)
    assert all(item.source_location is None and item.sink_location is None for item in taint_output.taint_evidence)
    assert all(item.source_location_status.value == "unknown" for item in taint_output.taint_evidence)
    assert all(item.sink_location_status.value == "unknown" for item in taint_output.taint_evidence)
    assert all(item.matched_file == findings_by_id[item.finding_id].file_path for item in taint_output.taint_evidence)
    assert all(
        item.matched_start.line == findings_by_id[item.finding_id].line_number
        for item in taint_output.taint_evidence
    )
    assert all(item.source_declaration_status.value == "available" for item in taint_output.taint_evidence)
    assert all(item.rules_file_sha256 for item in taint_output.taint_evidence)
    assert all(CANARY not in repr(item) for item in taint_output.taint_evidence)

    taint_review = render_review(
        taint,
        taint_output.taint_evidence,
        rules_file=TAINT_RULE,
        trusted_rules_directory=TRUSTED_RULES,
    )
    baseline_review = render_review(
        baseline,
        baseline_output.taint_evidence,
        rules_file=BASELINE_RULE,
        trusted_rules_directory=TRUSTED_RULES,
    )
    assert "검토 대상: 13건" in taint_review
    assert taint_review.count("근거 검증: 통과") == 13
    assert taint_review.count("Semgrep이 신뢰된 taint 규칙에 따른 매치를 보고했습니다.") == 13
    assert taint_review.count("전체 Source→Sink 경로는 증명되지 않았습니다.") == 13
    assert "검토 대상: 11건" in baseline_review
    assert baseline_review.count("근거 검증: 통과") == 11
    assert "탐지 유형: 일반 패턴" in baseline_review
    assert "확인 항목: 신뢰된 taint 규칙 매치 보고 [현재 자료에서 확인 불가]" in baseline_review
    assert CANARY not in taint_review
    assert CANARY not in baseline_review
    assert all(finding.status is FindingStatus.UNVERIFIED for finding in (*taint.findings, *baseline.findings))
    assert all(finding.confirmation is None for finding in (*taint.findings, *baseline.findings))

    for item in taint_output.taint_evidence:
        finding = findings_by_id[item.finding_id]
        gate = {
            result.claim_type: result
            for result in evaluate_all_claims(
                finding,
                evidence=item,
                scan_result=taint,
                rules_file=TAINT_RULE,
                trusted_rules_directory=TRUSTED_RULES,
            )
        }
        assert gate[ClaimType.MATCH_REPORTED].decision is ClaimDecision.SUPPORTED
        assert gate[ClaimType.TAINT_RULE_MATCH_REPORTED].decision is ClaimDecision.SUPPORTED
        assert gate[ClaimType.SOURCE_PATTERN_DECLARED].decision is ClaimDecision.SUPPORTED
        assert gate[ClaimType.SINK_PATTERN_DECLARED].decision is ClaimDecision.SUPPORTED
        assert gate[ClaimType.MATCH_LOCATION_OBSERVED].decision is ClaimDecision.SUPPORTED
        assert gate[ClaimType.SOURCE_LOCATION_IDENTIFIED].decision is ClaimDecision.UNAVAILABLE
        assert gate[ClaimType.SINK_ARGUMENT_LOCATION_IDENTIFIED].decision is ClaimDecision.UNAVAILABLE
        assert gate[ClaimType.FLOW_TRACE_AVAILABLE].decision is ClaimDecision.UNAVAILABLE
        assert gate[ClaimType.SANITIZER_MATCH_OBSERVED].decision is ClaimDecision.UNAVAILABLE
        assert gate[ClaimType.SANITIZER_EFFECTIVENESS_VERIFIED].decision is ClaimDecision.UNSUPPORTED_CLAIM
        assert gate[ClaimType.VULNERABILITY_CONFIRMED].decision is ClaimDecision.UNSUPPORTED_CLAIM
        assert all(result.finding_id == finding.finding_id for result in gate.values())
        summary = build_evidence_summary(
            finding,
            evidence=item,
            scan_result=taint,
            rules_file=TAINT_RULE,
            trusted_rules_directory=TRUSTED_RULES,
        )
        assert summary.finding_kind is FindingKind.TAINT
        assert summary.trusted_rule_declaration_status is RuleDeclarationStatus.VERIFIED
        assert summary.association_status is SummaryAssociationStatus.EXACT
        assert validate_evidence_summary(
            summary,
            finding,
            evidence=item,
            scan_result=taint,
            rules_file=TAINT_RULE,
            trusted_rules_directory=TRUSTED_RULES,
        ) == summary
        consumed = consume_evidence_summary(
            summary,
            finding,
            evidence=item,
            scan_result=taint,
            rules_file=TAINT_RULE,
            trusted_rules_directory=TRUSTED_RULES,
        )
        assert consumed.finding_kind is FindingKind.TAINT
        assert consumed.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
        assert not consumed.supports(ClaimType.SOURCE_LOCATION_IDENTIFIED)
        assert not consumed.supports(ClaimType.FLOW_TRACE_AVAILABLE)
        assert not consumed.supports(ClaimType.VULNERABILITY_CONFIRMED)
        assert CANARY not in summary.model_dump_json()
        assert CANARY not in consumed.model_dump_json()
        if item is taint_output.taint_evidence[0]:
            changed_finding = finding.model_copy(update={"title": "synthetic altered finding"})
            with pytest.raises(EvidenceConsumerError):
                consume_evidence_summary(
                    summary,
                    changed_finding,
                    evidence=item,
                    scan_result=taint,
                    rules_file=TAINT_RULE,
                    trusted_rules_directory=TRUSTED_RULES,
                )

    for finding in baseline.findings:
        pattern_gate = evaluate_all_claims(finding, scan_result=baseline)
        pattern_results = {item.claim_type: item for item in pattern_gate}
        assert pattern_results[ClaimType.MATCH_REPORTED].decision is ClaimDecision.SUPPORTED
        assert pattern_results[ClaimType.TAINT_RULE_MATCH_REPORTED].decision is ClaimDecision.UNAVAILABLE
        assert pattern_results[ClaimType.TAINT_RULE_MATCH_REPORTED].finding_id is None
        summary = build_evidence_summary(finding, scan_result=baseline)
        assert summary.finding_kind is FindingKind.PATTERN
        assert summary.trusted_rule_declaration_status is RuleDeclarationStatus.NOT_APPLICABLE
        assert summary.association_status is SummaryAssociationStatus.NOT_APPLICABLE
        assert validate_evidence_summary(summary, finding, scan_result=baseline) == summary
        consumed = consume_evidence_summary(summary, finding, scan_result=baseline)
        assert consumed.finding_kind is FindingKind.PATTERN
        assert consumed.supports(ClaimType.MATCH_REPORTED)
        assert not consumed.supports(ClaimType.TAINT_RULE_MATCH_REPORTED)
        assert CANARY not in summary.model_dump_json()
        assert CANARY not in consumed.model_dump_json()

    taint_plain = {
        path: (line, rule_id)
        for (path, rule_id), (line, _severity, _cwe) in _finding_locations(taint).items()
        if rule_id == "experimental.javascript-eval-taint"
    }
    taint_sanitized = {
        path: (line, rule_id)
        for (path, rule_id), (line, _severity, _cwe) in _finding_locations(taint).items()
        if rule_id == "experimental.javascript-eval-taint-with-synthetic-sanitizer"
    }
    assert taint_plain == {
        path: (line, "experimental.javascript-eval-taint")
        for path, line in EXPECTED_PLAIN_TAINT.items()
    }
    assert taint_sanitized == {
        path: (line, "experimental.javascript-eval-taint-with-synthetic-sanitizer")
        for path, line in EXPECTED_MODELED_SANITIZER.items()
    }
    expected_sanitizer_policy_negatives = set("DEGL")
    observed_sanitizer_policy_negatives = set("ABCDEFGHKL") - set(taint_sanitized)
    assert (len(set(taint_sanitized) & set(EXPECTED_MODELED_SANITIZER)),
            len(set(taint_sanitized) & expected_sanitizer_policy_negatives),
            len(set(EXPECTED_MODELED_SANITIZER) - set(taint_sanitized)),
            len(observed_sanitizer_policy_negatives & expected_sanitizer_policy_negatives)) == (6, 0, 0, 4)
    assert {
        path: (line, rule_id, severity, cwe)
        for (path, rule_id), (line, severity, cwe) in _finding_locations(baseline).items()
    } == {
        path: (line, "baseline.javascript-dynamic-eval", "high", "CWE-95")
        for path, line in EXPECTED_BASELINE.items()
    }

    for finding in (*taint.findings, *baseline.findings):
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-95"
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.confirmation is None
        assert CANARY not in finding.model_dump_json()
        assert CANARY not in repr(finding)

    raw = _raw_taint_json(executable, target)
    assert raw.get("version") == REQUIRED_VERSION
    assert raw.get("engine_requested") == "OSS"
    assert raw.get("errors") == []
    scanned = raw.get("paths", {}).get("scanned") if isinstance(raw.get("paths"), dict) else None
    assert isinstance(scanned, list) and len(scanned) == len(list(FIXTURES.iterdir()))
    raw_results = raw.get("results")
    assert isinstance(raw_results, list) and len(raw_results) == len(taint.findings)
    assert {item.get("extra", {}).get("engine_kind") for item in raw_results} == {"OSS"}
    # Semgrep 1.182.1 reported sink locations and match snippets, but no explicit
    # source location, metavariable map, or dataflow trace in this OSS JSON.
    for item in raw_results:
        extra = item.get("extra", {})
        assert "dataflow_trace" not in item
        assert "metavars" not in item
        assert "dataflow_trace" not in extra
        assert "metavars" not in extra
        assert isinstance(item.get("start"), dict)
        assert isinstance(item.get("end"), dict)

    # The CLI accepts --dataflow-traces with JSON + OSS, but its documented
    # output scope excludes JSON. Confirm actual results and locations are
    # unchanged and no trace field was added.
    traced_raw = _raw_taint_json(executable, target, dataflow_traces=True)
    traced_results = traced_raw.get("results")
    assert traced_raw.get("version") == REQUIRED_VERSION
    assert traced_raw.get("engine_requested") == "OSS"
    assert traced_raw.get("errors") == []
    assert isinstance(traced_results, list)
    assert len(traced_results) == len(raw_results)
    assert [
        (item.get("check_id"), item.get("path"), item.get("start"), item.get("end"))
        for item in traced_results
    ] == [
        (item.get("check_id"), item.get("path"), item.get("start"), item.get("end"))
        for item in raw_results
    ]
    assert all("dataflow_trace" not in item.get("extra", {}) for item in traced_results)
    parsed_with_trace_option = parse_semgrep_json(json.dumps(traced_raw).encode(), target)
    assert [finding.finding_id for finding in parsed_with_trace_option.findings] == [
        finding.finding_id for finding in taint.findings
    ]

    # In-scope cases A-H, K, L have deterministic expected flow labels.
    # I/J depend on interprocedural/interfile analysis and are reported separately.
    in_scope = set("ABCDEFGHKL")
    expected_positive = set("ABCFGHK")
    observed_positive = {Path(path).stem[0] for path in taint_plain}
    tp = len(observed_positive & expected_positive)
    fp = len(observed_positive & (in_scope - expected_positive))
    fn = len(expected_positive - observed_positive)
    tn = len((in_scope - expected_positive) - observed_positive)
    assert (tp, fp, fn, tn) == (7, 0, 0, 3)
    assert {"I", "J"}.isdisjoint(observed_positive)
