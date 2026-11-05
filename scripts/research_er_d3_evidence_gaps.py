"""Reproduce ER-D3 evidence-gap experiments with local synthetic inputs only.

This is a research harness, not a product CLI. It reports only bounded,
allowlisted observations; source text, raw Semgrep JSON, digests, handles, and
absolute paths are never printed or persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ai_code_security_analyzer.scan_evidence_manifest import EvidenceStatus, parse_scope_evidence
from ai_code_security_analyzer.semgrep_adapter import MAX_OUTPUT_BYTES, ScanStatus, SemgrepAdapter, _run_process
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


EXPECTED_SEMGREP = "1.182.1"
MAX_FIXTURE_FILE_BYTES = 64 * 1024
MAX_PROCESS_OUTPUT_BYTES = 2_000_000
MAX_PROCESS_SECONDS = 60


def _write(path: Path, content: str) -> None:
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_FIXTURE_FILE_BYTES:
        raise RuntimeError("fixture_size_limit_exceeded")
    path.write_bytes(encoded)


def _sha256(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_FIXTURE_FILE_BYTES:
        raise RuntimeError("fixture_size_limit_exceeded")
    return hashlib.sha256(data).hexdigest()


def _scan(target: Path, rules_directory: Path):
    settings = ApiSettings(
        target_directory=target.resolve(),
        trusted_rules_directory=rules_directory.resolve(),
        api_token=secrets.token_urlsafe(32),
    )
    return ScanService(settings)._scan_with_manifest("local-project", "baseline")


def _semgrep_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }


def _invoke_semgrep(target: Path, rules_file: Path, *, verbose: bool, home: Path):
    command = [
        "semgrep", "scan", "--json", "--metrics=off", "--disable-version-check",
        "--oss-only", "--no-autofix", "--config", rules_file.name,
    ]
    if verbose:
        command.append("--verbose")
    command.extend(["--", str(target.resolve())])
    completed = _run_process(command, rules_file.parent, _semgrep_environment(home), MAX_PROCESS_SECONDS)
    if completed.exit_code != 0:
        raise RuntimeError("semgrep_execution_failed")
    return completed


def _observed_scope(document: dict[str, Any], target: Path):
    scope = parse_scope_evidence(document, target.resolve())
    if scope.scanned_status is not EvidenceStatus.OBSERVED:
        raise RuntimeError("scanned_scope_not_observed")
    return scope


def _experiment_rule_bytes(repository_rules: Path, root: Path) -> dict[str, object]:
    target = root / "rule-target"
    target.mkdir()
    _write(target / "sample.js", 'function sample(input) { return eval(input); }\n')
    first_rules = root / "trusted-a"
    second_rules = root / "trusted-b"
    first_rules.mkdir()
    second_rules.mkdir()
    original = repository_rules / "security-baseline.yml"
    if original.stat().st_size > MAX_FIXTURE_FILE_BYTES:
        raise RuntimeError("trusted_rule_size_limit_exceeded")
    original_bytes = original.read_bytes()
    (first_rules / original.name).write_bytes(original_bytes)
    (second_rules / original.name).write_bytes(original_bytes + b"\n# ER-D3 synthetic byte-identity probe\n")

    first_before = _sha256(first_rules / original.name)
    same_copy_digest = _sha256(first_rules / original.name) == first_before
    second_digest = _sha256(second_rules / original.name)
    changed_copy_digest = first_before != second_digest
    response_a, manifest_a = _scan(target, first_rules)
    response_b, manifest_b = _scan(target, second_rules)
    if response_a.semgrep_version != EXPECTED_SEMGREP or response_b.semgrep_version != EXPECTED_SEMGREP:
        raise RuntimeError("unexpected_semgrep_version")
    if response_a.scan_status is not ScanStatus.COMPLETED or response_b.scan_status is not ScanStatus.COMPLETED:
        raise RuntimeError("rule_identity_scan_not_completed")
    if tuple(item.finding_id for item in response_a.findings) != tuple(item.finding_id for item in response_b.findings):
        raise RuntimeError("comment_only_rule_copy_changed_findings")
    if manifest_a.rule_profile_id != manifest_b.rule_profile_id:
        raise RuntimeError("rule_profile_id_changed")
    if manifest_a.rule_evidence.selected_rule_file_id != manifest_b.rule_evidence.selected_rule_file_id:
        raise RuntimeError("selected_rule_file_id_changed")
    if manifest_a.rule_evidence.loaded_identity_status is not EvidenceStatus.UNVERIFIED:
        raise RuntimeError("loaded_identity_contract_changed")
    return {
        "profile_id_equal": manifest_a.rule_profile_id == manifest_b.rule_profile_id,
        "selected_file_id_equal": manifest_a.rule_evidence.selected_rule_file_id == manifest_b.rule_evidence.selected_rule_file_id,
        "same_copy_digest_reproducible": same_copy_digest,
        "changed_copy_digest_distinguished": changed_copy_digest,
        "comment_only_variant_finding_ids_equal": True,
        "manifest_byte_identity_status": manifest_a.rule_evidence.byte_identity_status.value,
        "manifest_loaded_identity_status": manifest_a.rule_evidence.loaded_identity_status.value,
        "semgrep_loaded_rule_inventory_observed": False,
    }


def _experiment_source_change(repository_rules: Path, root: Path) -> dict[str, object]:
    target = root / "source-target"
    target.mkdir()
    _write(target / "stable.js", 'function stable(input) { return eval(input); }\n')
    retired = target / "retired.js"
    _write(retired, 'function retired(input) { return eval(input); }\n')
    rules = repository_rules.resolve()
    before_digest = _sha256(retired)
    baseline, baseline_manifest = _scan(target, rules)
    _write(retired, 'function retired(input) { return String(input); }\n')
    after_digest = _sha256(retired)
    current, current_manifest = _scan(target, rules)
    if baseline.semgrep_version != EXPECTED_SEMGREP or current.semgrep_version != EXPECTED_SEMGREP:
        raise RuntimeError("unexpected_semgrep_version")
    if baseline.scan_status is not ScanStatus.COMPLETED or current.scan_status is not ScanStatus.COMPLETED:
        raise RuntimeError("source_change_scan_not_completed")
    baseline_files = {item.file_path for item in baseline.findings}
    current_files = {item.file_path for item in current.findings}
    if not {"stable.js", "retired.js"}.issubset(baseline_files) or "retired.js" in current_files or "stable.js" not in current_files:
        raise RuntimeError("source_change_expected_findings_missing")
    if baseline_manifest.scan_ref == current_manifest.scan_ref:
        raise RuntimeError("scan_references_not_distinct")
    return {
        "experimenter_observed_synthetic_file_bytes_changed": before_digest != after_digest,
        "baseline_retired_finding_observed": "retired.js" in baseline_files,
        "current_retired_finding_observed": "retired.js" in current_files,
        "stable_finding_observed_in_both": "stable.js" in baseline_files and "stable.js" in current_files,
        "product_manifest_contains_general_source_digest": False,
        "source_digest_retained_or_printed": False,
        "source_change_causation_proven_by_digest": False,
        "manifest_source_snapshot_limitation": "source_snapshot_not_collected" in baseline_manifest.limitations,
    }


def _experiment_scope(repository_rules: Path, root: Path, home: Path) -> dict[str, object]:
    target = root / "scope-target"
    target.mkdir()
    _write(target / "normal.js", 'function normal(input) { return eval(input); }\n')
    _write(target / "ignored.js", 'function ignored(input) { return eval(input); }\n')
    _write(target / ".semgrepignore", "ignored.js\n")
    rules_file = repository_rules / "security-baseline.yml"

    # First path uses the unchanged production adapter invocation (non-verbose).
    default = SemgrepAdapter(repository_rules)._scan_with_evidence(target.resolve(), rules_file.resolve())
    if default.result.status is not ScanStatus.COMPLETED or default.result.semgrep_version != EXPECTED_SEMGREP:
        raise RuntimeError("default_scope_scan_not_completed")

    # The second invocation is an isolated experiment, not a product option change.
    verbose = _invoke_semgrep(target, rules_file, verbose=True, home=home)
    parsed_verbose = _parse_semgrep_json_internal(verbose.stdout, target.resolve())
    default_finding_projection = {
        (item.finding_id, item.file_path, item.rule_id) for item in default.result.findings
    }
    verbose_finding_projection = {
        (item.finding_id, item.file_path, item.rule_id) for item in parsed_verbose.parsed.findings
    }
    if verbose_finding_projection != default_finding_projection:
        raise RuntimeError("verbose_finding_set_differed")
    verbose_scope = _observed_scope(parsed_verbose.document, target)
    if "ignored.js" not in {item.path for item in verbose_scope.skipped_paths}:
        raise RuntimeError("verbose_skip_observation_missing")
    ignored = next(item for item in verbose_scope.skipped_paths if item.path == "ignored.js")
    if ignored.reason_code != "semgrepignore_patterns_match":
        raise RuntimeError("unexpected_skip_reason")
    if default.scope_evidence.skipped_status is not EvidenceStatus.NOT_COLLECTED:
        raise RuntimeError("default_skip_contract_changed")
    if verbose_scope.completeness_status is not EvidenceStatus.UNVERIFIED:
        raise RuntimeError("verbose_scope_overstated_completeness")
    if verbose_scope.errors_status is not EvidenceStatus.OBSERVED or verbose_scope.errors_count != 0:
        raise RuntimeError("verbose_errors_summary_not_observed")
    return {
        "default_invocation_id": "semgrep-json-local-v1",
        "default_scanned_paths_observed": "normal.js" in default.scope_evidence.scanned_paths,
        "default_ignored_path_absent_from_scanned": "ignored.js" not in default.scope_evidence.scanned_paths,
        "default_skipped_status": default.scope_evidence.skipped_status.value,
        "verbose_scanned_paths_observed": "normal.js" in verbose_scope.scanned_paths,
        "verbose_ignored_path_skip_observed": True,
        "verbose_skip_reason_code": ignored.reason_code,
        "finding_projection_equal_between_invocations": verbose_finding_projection == default_finding_projection,
        "verbose_parser_issue_codes": list(parsed_verbose.parsed.issues),
        "verbose_product_status_if_current_issue_policy_applies": (
            ScanStatus.PARTIAL.value if parsed_verbose.parsed.issues else ScanStatus.COMPLETED.value
        ),
        "verbose_errors_count": verbose_scope.errors_count,
        "verbose_skipped_rules_count": verbose_scope.skipped_rules_count,
        "scope_completeness_status": verbose_scope.completeness_status.value,
        "all_rules_applied_or_scan_complete_proven": False,
    }


def main() -> None:
    if MAX_OUTPUT_BYTES != MAX_PROCESS_OUTPUT_BYTES:
        raise SystemExit("adapter_output_limit_changed")
    repository = Path(__file__).resolve().parents[1]
    repository_rules = repository / "rules"
    baseline_rule = repository_rules / "security-baseline.yml"
    original_rule_digest = _sha256(baseline_rule)

    with tempfile.TemporaryDirectory(prefix="er-d3-synthetic-") as temporary:
        root = Path(temporary).resolve()
        home = root / "semgrep-home"
        home.mkdir()
        version_result = subprocess.run(
            ["semgrep", "--version"], capture_output=True, text=True, timeout=10, check=True,
            env=_semgrep_environment(home),
        )
        version = version_result.stdout.strip()
        if version != EXPECTED_SEMGREP:
            raise SystemExit("required_semgrep_version_mismatch")
        results = {
            "contract": "er-d3-feasibility-observations/v1",
            "semgrep_version": version,
            "fixture_scope": "synthetic_javascript_and_copies_of_trusted_local_baseline_rules",
            "experiments": {
                "A_selected_rule_file_bytes": _experiment_rule_bytes(repository_rules, root),
                "B_source_change": _experiment_source_change(repository_rules, root),
                "C_scope_collection": _experiment_scope(repository_rules, root, home),
            },
            "trusted_repository_rule_file_unchanged": _sha256(baseline_rule) == original_rule_digest,
            "raw_source_or_semgrep_json_persisted": False,
            "temporary_inputs_removed_on_exit": True,
        }
    print(json.dumps(results, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
