"""Bounded real Semgrep trace feasibility checks on synthetic fixtures only."""

from __future__ import annotations

import json
import os
import shutil
from collections import Counter
from pathlib import Path

import pytest

from ai_code_security_analyzer.models import FindingStatus
from ai_code_security_analyzer.semgrep_adapter import (
    MAX_OUTPUT_BYTES,
    SCAN_TIMEOUT_SECONDS,
    _run_process,
)
from ai_code_security_analyzer.semgrep_parser import (
    InvalidSemgrepJson,
    _finding_id,
    _parse_semgrep_json_internal,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "taint_trace_phase6i"
MANIFEST = FIXTURES / "manifest.json"
RULES = (
    ROOT / "rules/experimental/javascript-eval-taint.yml",
    ROOT / "rules/experimental/javascript-eval-source-context.yml",
    ROOT / "rules/experimental/javascript-command-injection-taint.yml",
)
REQUIRED_VERSION = "1.182.1"
PRIVACY_CANARY = "PHASE6I_TRACE_" + "PRIVATE_CANARY"


def _assert_canary_absent(value: object) -> None:
    if PRIVACY_CANARY in repr(value):
        pytest.fail("phase6i_sensitive_value_exposed")


def _require_semgrep() -> str:
    executable = shutil.which("semgrep")
    if executable is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("phase6i_semgrep_required_but_missing")
        pytest.skip("Semgrep CLI is not installed")
    return executable


def _copy_corpus(target: Path) -> dict[str, object]:
    target.mkdir()
    for case in FIXTURES.iterdir():
        if case.is_dir():
            shutil.copytree(case, target / case.name)
        elif case.suffix == ".js":
            shutil.copyfile(case, target / case.name)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    # This source excerpt canary exists only in the temporary test target.
    (target / "Z_privacy_canary.js").write_text(
        f'function run(req) {{ eval(req.query.code); /* {PRIVACY_CANARY} */ }}\n',
        encoding="utf-8",
    )
    return manifest


def _run_semgrep(executable: str, target: Path, output: str, *, traces: bool) -> dict[str, object]:
    with pytest.MonkeyPatch.context() as patch:
        # Keep Semgrep settings local and deterministic. No registry config is used.
        mode = "trace" if traces else "plain"
        home = target.parent / f"semgrep-home-{output.removeprefix('--')}-{mode}"
        home.mkdir()
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
        patch.setenv("SEMGREP_SEND_METRICS", "off")
        patch.setenv("SEMGREP_ENABLE_VERSION_CHECK", "0")
        args = [
            executable, "scan", output, "--metrics=off", "--disable-version-check",
            "--oss-only", "--no-autofix",
        ]
        if traces:
            args.append("--dataflow-traces")
        for rule in RULES:
            args.extend(["--config", rule.name])
        args.extend(["--", str(target)])
        result = _run_process(args, RULES[0].parent, env, SCAN_TIMEOUT_SECONDS)
    assert len(result.stdout) <= MAX_OUTPUT_BYTES
    assert result.exit_code == 0
    try:
        document = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pytest.fail("phase6i_semgrep_output_invalid")
    assert isinstance(document, dict)
    return document


def _safe_relative_path(raw: object, root: Path) -> str | None:
    if not isinstance(raw, str) or not raw or "://" in raw or raw.startswith(("file:", "data:")):
        return None
    try:
        path = Path(raw)
        resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
        return resolved.relative_to(root.resolve()).as_posix()
    except (OSError, ValueError, RuntimeError):
        return None


def _coordinate(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def _json_summary(document: dict[str, object], root: Path) -> dict[str, object]:
    rows = document.get("results")
    assert isinstance(rows, list)
    states: Counter[str] = Counter()
    signatures: Counter[tuple[object, ...]] = Counter()
    finding_ids: list[str] = []
    by_case: Counter[tuple[str, str]] = Counter()
    join_count = 0
    invalid_locations = 0
    trace_key_names: set[str] = set()
    paths = document.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    assert isinstance(scanned, list)
    normalized_scanned = {_safe_relative_path(path, root) for path in scanned}

    encoded = json.dumps(document).encode("utf-8")
    try:
        parsed = _parse_semgrep_json_internal(encoded, root)
    except InvalidSemgrepJson:
        pytest.fail("phase6i_semgrep_json_contract_invalid")
    assert len(parsed.result_findings) == len(rows)

    for row, finding in zip(rows, parsed.result_findings, strict=True):
        if not isinstance(row, dict):
            invalid_locations += 1
            continue
        candidate_values = []
        for container in (row, row.get("extra") if isinstance(row.get("extra"), dict) else {}):
            for key in ("dataflow_trace", "taint_trace", "trace"):
                if key in container:
                    candidate_values.append(container[key])
                    trace_key_names.add(key)
        if not candidate_values:
            states["absent"] += 1
        elif any(not isinstance(value, (dict, list)) for value in candidate_values):
            states["malformed"] += 1
        elif all(not value for value in candidate_values):
            states["empty"] += 1
        else:
            # OSS trace content is not understood, retained, or promoted.
            states["unsupported"] += 1

        rule_id = row.get("check_id")
        path = _safe_relative_path(row.get("path"), root)
        start, end = row.get("start"), row.get("end")
        start = start if isinstance(start, dict) else {}
        end = end if isinstance(end, dict) else {}
        coords = tuple(_coordinate(value) for value in (
            start.get("line"), start.get("col"), end.get("line"), end.get("col")
        ))
        if not isinstance(rule_id, str) or path is None or any(value is None for value in coords):
            invalid_locations += 1
            continue
        signature = (rule_id, path, *coords)
        signatures[signature] += 1
        case = Path(path).stem
        by_case[(case, rule_id)] += 1
        if finding is None:
            continue
        expected_id = _finding_id(rule_id, path, *coords)
        if (
            finding.finding_id == expected_id
            and finding.rule_id == rule_id
            and finding.file_path == path
            and finding.line_number == coords[0]
            and finding.status is FindingStatus.UNVERIFIED
            and finding.confirmation is None
        ):
            join_count += 1
            finding_ids.append(finding.finding_id)

    return {
        "result_count": len(rows),
        "trace_states": dict(states),
        "trace_key_names": sorted(trace_key_names),
        "signatures": signatures,
        "finding_ids": finding_ids,
        "case_rule_counts": by_case,
        "valid_finding_joins": join_count,
        "invalid_locations": invalid_locations,
        "duplicate_signatures": sum(count - 1 for count in signatures.values() if count > 1),
        "scanned_files": normalized_scanned,
    }


def _sarif_summary(document: dict[str, object], root: Path) -> dict[str, object]:
    assert document.get("version") == "2.1.0"
    runs = document.get("runs")
    assert isinstance(runs, list) and len(runs) == 1
    run = runs[0]
    assert isinstance(run, dict)
    tool = run.get("tool")
    assert isinstance(tool, dict) and isinstance(tool.get("driver"), dict)
    assert tool["driver"].get("name") == "Semgrep OSS"
    rows = run.get("results")
    assert isinstance(rows, list)
    states: Counter[str] = Counter()
    signatures: Counter[tuple[object, ...]] = Counter()
    invalid_locations = 0
    for row in rows:
        if not isinstance(row, dict):
            invalid_locations += 1
            continue
        flows = row.get("codeFlows", "__absent__")
        if flows == "__absent__":
            states["absent"] += 1
        elif not isinstance(flows, list):
            states["malformed"] += 1
        elif not flows:
            states["empty"] += 1
        else:
            # We only record presence; thread-flow values may contain snippets.
            states["present_unsupported"] += 1

        locations = row.get("locations")
        if not isinstance(locations, list) or len(locations) != 1:
            invalid_locations += 1
            continue
        location = locations[0]
        physical = location.get("physicalLocation") if isinstance(location, dict) else None
        physical = physical if isinstance(physical, dict) else {}
        artifact = physical.get("artifactLocation")
        artifact = artifact if isinstance(artifact, dict) else {}
        region = physical.get("region")
        region = region if isinstance(region, dict) else {}
        path = _safe_relative_path(artifact.get("uri"), root)
        values = tuple(_coordinate(region.get(key)) for key in (
            "startLine", "startColumn", "endLine", "endColumn"
        ))
        rule_id = row.get("ruleId")
        if path is None or not isinstance(rule_id, str) or any(value is None for value in values):
            invalid_locations += 1
            continue
        signatures[(rule_id, path, *values)] += 1
    return {
        "result_count": len(rows),
        "trace_states": dict(states),
        "signatures": signatures,
        "invalid_locations": invalid_locations,
        "duplicate_signatures": sum(count - 1 for count in signatures.values() if count > 1),
    }


def test_phase6i_corpus_manifest_is_fixed_and_synthetic() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases = manifest.get("cases")
    assert manifest.get("dataset_version") == "phase6i-trace-feasibility-dev-v1"
    assert manifest.get("vulnerability_confirmation") == "NOT_EVALUATED"
    assert isinstance(cases, list) and len(cases) == 21
    ids = [case.get("case_id") for case in cases]
    assert len(ids) == len(set(ids))
    assert all(case.get("vulnerability_confirmation") == "NOT_EVALUATED" for case in cases)
    assert all(case.get("rule_signal") in {"positive", "negative", "out_of_scope"} for case in cases)
    assert all(case.get("source_context") in {
        "framework_context_observed", "generic_object_context", "insufficient_context", "out_of_scope"
    } for case in cases)
    assert all(case.get("security_review_relevance") in {"review_worthy", "lower_priority", "undetermined"} for case in cases)


def test_phase6i_real_oss_trace_option_and_finding_association(tmp_path: Path) -> None:
    executable = _require_semgrep()
    target = tmp_path / "synthetic-target"
    manifest = _copy_corpus(target)

    plain_json = _run_semgrep(executable, target, "--json", traces=False)
    trace_json = _run_semgrep(executable, target, "--json", traces=True)
    trace_sarif = _run_semgrep(executable, target, "--sarif", traces=True)

    assert plain_json.get("version") == trace_json.get("version") == REQUIRED_VERSION
    assert plain_json.get("engine_requested") == trace_json.get("engine_requested") == "OSS"
    assert plain_json.get("errors") == trace_json.get("errors") == []
    normal = _json_summary(plain_json, target)
    traced_json = _json_summary(trace_json, target)
    sarif = _sarif_summary(trace_sarif, target)

    assert normal["signatures"] == traced_json["signatures"] == sarif["signatures"]
    assert normal["result_count"] == traced_json["result_count"] == sarif["result_count"]
    assert normal["duplicate_signatures"] == traced_json["duplicate_signatures"] == sarif["duplicate_signatures"] == 0
    assert normal["invalid_locations"] == traced_json["invalid_locations"] == sarif["invalid_locations"] == 0
    assert traced_json["valid_finding_joins"] == traced_json["result_count"]
    assert len(traced_json["finding_ids"]) == len(set(traced_json["finding_ids"]))
    assert traced_json["trace_states"] == {"absent": traced_json["result_count"]}
    assert traced_json["trace_key_names"] == []
    assert sarif["trace_states"] == {"absent": sarif["result_count"]}

    expected = {
        case["case_id"]: (set(case["expected_rule_ids"]), case["expected_finding_count"])
        for case in manifest["cases"]
    }
    expected_scanned = {f"{case_id}.js" for case_id in expected} | {"Z_privacy_canary.js"}
    assert normal["scanned_files"] == traced_json["scanned_files"] == expected_scanned
    observed: dict[str, set[str]] = {}
    for (case, rule_id), count in traced_json["case_rule_counts"].items():
        observed.setdefault(case, set()).add(rule_id)
        case_expected = expected.get(case)
        if case_expected is None:
            assert case == "Z_privacy_canary"
            assert rule_id in {
                "experimental.javascript-eval-taint",
                "experimental.javascript-eval-taint-with-synthetic-sanitizer",
            }
            assert count == 1
        else:
            assert count <= case_expected[1]
    for case, (rule_ids, expected_count) in expected.items():
        assert observed.get(case, set()) == rule_ids, case
        actual_count = sum(count for (name, _rule), count in traced_json["case_rule_counts"].items() if name == case)
        assert actual_count == expected_count

    # Only bounded normalized summaries are examined; neither raw output nor excerpts are returned.
    _assert_canary_absent(normal)
    _assert_canary_absent(traced_json)
    _assert_canary_absent(sarif)
