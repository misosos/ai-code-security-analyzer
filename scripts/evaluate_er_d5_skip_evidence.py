#!/usr/bin/env python3
"""Reproduce the ER-D5 non-verbose vs investigation skip-evidence comparison.

Uses a temporary synthetic JavaScript target, the trusted repository baseline
rules, the real v1/v2 FastAPI routes, the process-local evidence registry, and
the existing ER-C2 evaluator. Output is a deliberately small public projection.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.services.scan_service import ApiSettings


EXPECTED_PYTHON = (3, 12, 7)
EXPECTED_SEMGREP = "1.182.1"
REQUEST = {"target_id": "local-project", "rule_profile_id": "baseline"}


def _require_environment(repository: Path) -> None:
    if sys.version_info[:3] != EXPECTED_PYTHON:
        raise RuntimeError("python_version_mismatch")
    semgrep = subprocess.run(
        ["semgrep", "--version"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )
    if semgrep.returncode != 0 or semgrep.stdout.strip() != EXPECTED_SEMGREP:
        raise RuntimeError("semgrep_version_mismatch")


def _partition(baseline: dict, current: dict) -> dict[str, list[str]]:
    base = {finding["finding_id"] for finding in baseline["findings"]}
    now = {finding["finding_id"] for finding in current["findings"]}
    return {
        "shared": sorted(base & now),
        "baselineOnly": sorted(base - now),
        "currentOnly": sorted(now - base),
    }


def _scan(client: TestClient, route: str, headers: dict[str, str]) -> dict:
    response = client.post(route, headers=headers, json=REQUEST)
    if response.status_code != 200:
        raise RuntimeError("scan_request_failed")
    if route == "/api/v1/scans":
        if "semgrepignore_patterns_match" in response.text:
            raise RuntimeError("non_verbose_skip_reason_unexpectedly_public")
        if '"paths"' in response.text:
            raise RuntimeError("non_verbose_scope_unexpectedly_public")
    return response.json()


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    _require_environment(repository)
    rules = repository / "rules"
    if not (rules / "security-baseline.yml").is_file():
        raise RuntimeError("trusted_baseline_rules_unavailable")

    with tempfile.TemporaryDirectory(prefix="er-d5-synthetic-") as temporary:
        root = Path(temporary).resolve(strict=True)
        target = root / "project"
        target.mkdir(mode=0o700)
        (target / "stable.js").write_text(
            "function stable(input) { return eval(input); }\n", encoding="utf-8"
        )
        (target / "retired.js").write_text(
            "function retired(input) { return eval(input); }\n", encoding="utf-8"
        )
        settings = ApiSettings(
            target_directory=target,
            trusted_rules_directory=rules,
            api_token=secrets.token_urlsafe(32),
            allowed_hosts=("testserver",),
        )
        app = create_app(settings, investigation_api_enabled=True)
        headers = {"X-Local-API-Token": settings.api_token}
        handles: list[str] = []
        session_handle: str | None = None

        with TestClient(app) as client:
            # Experiment A: ordinary v1 scans. Semgrep's default non-verbose
            # output does not provide the ignore reason to the public contract.
            basic_baseline = _scan(client, "/api/v1/scans", headers)
            (target / ".semgrepignore").write_text("retired.js\n", encoding="utf-8")
            basic_current = _scan(client, "/api/v1/scans", headers)
            basic_partition = _partition(basic_baseline, basic_current)
            if basic_baseline["scan_status"] != "completed" or basic_current["scan_status"] != "completed":
                raise RuntimeError("unexpected_non_verbose_status")
            if len(basic_partition["baselineOnly"]) != 1 or len(basic_partition["shared"]) != 1:
                raise RuntimeError("unexpected_non_verbose_finding_partition")

            # Experiment B: two independent v2 verbose Runs only. The v1 and v2
            # Runs are intentionally never mixed into one investigation session.
            (target / ".semgrepignore").unlink()
            verbose_baseline = _scan(client, "/api/v2/investigation-scans", headers)
            handles.append(verbose_baseline["run_handle"])
            (target / ".semgrepignore").write_text("retired.js\n", encoding="utf-8")
            verbose_current = _scan(client, "/api/v2/investigation-scans", headers)
            handles.append(verbose_current["run_handle"])
            if verbose_baseline["run_handle"] == verbose_current["run_handle"]:
                raise RuntimeError("run_handle_collision")

            base_findings = verbose_baseline["scan"]["findings"]
            base_retired = next((item for item in base_findings if item["file_path"] == "retired.js"), None)
            base_stable = next((item for item in base_findings if item["file_path"] == "stable.js"), None)
            if base_retired is None or base_stable is None:
                raise RuntimeError("verbose_baseline_fixture_mismatch")
            verbose_partition = _partition(verbose_baseline["scan"], verbose_current["scan"])
            if verbose_partition != basic_partition:
                raise RuntimeError("finding_partition_differs_between_modes")
            if verbose_current["scan"]["scan_status"] != "partial" or verbose_current["scan"]["completed"] is not False:
                raise RuntimeError("verbose_partial_status_not_preserved")

            session_response = client.post(
                "/api/v2/investigations",
                headers=headers,
                json={
                    "baseline_handle": verbose_baseline["run_handle"],
                    "current_handle": verbose_current["run_handle"],
                },
            )
            if session_response.status_code != 201:
                raise RuntimeError("session_binding_failed")
            session_handle = session_response.json()["investigation_handle"]
            evaluation_response = client.post(
                "/api/v2/investigations/evaluate",
                headers=headers,
                json={"investigation_handle": session_handle},
            )
            if evaluation_response.status_code != 200:
                raise RuntimeError("evaluation_failed")
            evaluation = evaluation_response.json()
            retired = next((item for item in evaluation["findings"] if item["finding_id"] == base_retired["finding_id"]), None)
            if retired is None:
                raise RuntimeError("baseline_only_finding_missing")

            baseline_run = app.state.investigation_registry.get_run(verbose_baseline["run_handle"])
            current_run = app.state.investigation_registry.get_run(verbose_current["run_handle"])
            scope = current_run.manifest.scope_evidence
            if baseline_run.manifest.execution_evidence.invocation_id != "semgrep-json-investigation-verbose-v1":
                raise RuntimeError("baseline_invocation_identity_mismatch")
            if current_run.manifest.execution_evidence.invocation_id != "semgrep-json-investigation-verbose-v1":
                raise RuntimeError("current_invocation_identity_mismatch")
            if scope.skipped_status.value != "OBSERVED" or not any(
                item.path == "retired.js" and item.reason_code == "semgrepignore_patterns_match"
                for item in scope.skipped_paths
            ):
                raise RuntimeError("skip_evidence_not_observed")
            if scope.completeness_status.value != "UNVERIFIED":
                raise RuntimeError("scope_completeness_overstated")
            if evaluation["comparability"] != "INCOMPARABLE" or evaluation["overall_assessment"] != "INCOMPARABLE":
                raise RuntimeError("partial_run_promoted_to_comparable")
            if retired["category"] != "baselineOnly" or retired["path_observation"] != "PATH_EXPLICITLY_SKIPPED":
                raise RuntimeError("skip_observation_projection_mismatch")
            if retired["skip_hypothesis"] != "SUPPORTED":
                raise RuntimeError("skip_hypothesis_projection_mismatch")
            if "source_snapshot_not_collected" not in evaluation["limitation_codes"]:
                raise RuntimeError("source_limitation_missing")
            if "scope_completeness_unverified" not in evaluation["limitation_codes"]:
                raise RuntimeError("scope_limitation_missing")
            if any(secret in evaluation_response.text for secret in (settings.api_token, "function retired")):
                raise RuntimeError("sensitive_data_disclosed")

            # Explicitly release all temporary evidence, then assert it cannot
            # be reused. No Handle is emitted in the output projection.
            released_session = client.post(
                "/api/v2/investigation-release", headers=headers,
                json={"kind": "investigation", "handle": session_handle},
            )
            if released_session.status_code != 204:
                raise RuntimeError("session_release_failed")
            unavailable = client.post(
                "/api/v2/investigations/evaluate", headers=headers,
                json={"investigation_handle": session_handle},
            )
            if unavailable.status_code != 404 or unavailable.json() != {"error": "evidence_unavailable"}:
                raise RuntimeError("released_session_reused")
            session_handle = None
            for handle in handles:
                response = client.post(
                    "/api/v2/investigation-release", headers=headers,
                    json={"kind": "run", "handle": handle},
                )
                if response.status_code != 204:
                    raise RuntimeError("run_release_failed")

            print(json.dumps({
                "contract": "er-d5-skip-evidence-observation/v1",
                "python": ".".join(map(str, sys.version_info[:3])),
                "semgrep": EXPECTED_SEMGREP,
                "fixture": "synthetic_javascript_with_trusted_local_baseline_rules",
                "non_verbose": {
                    "transport": "POST /api/v1/scans",
                    "baseline_status": basic_baseline["scan_status"],
                    "current_status": basic_current["scan_status"],
                    "finding_partition_counts": {key: len(value) for key, value in basic_partition.items()},
                    "skip_reason_in_public_response": False,
                },
                "investigation_verbose": {
                    "transport": "POST /api/v2/investigation-scans plus session/evaluate",
                    "baseline_status": verbose_baseline["scan"]["scan_status"],
                    "current_status": verbose_current["scan"]["scan_status"],
                    "current_completed": verbose_current["scan"]["completed"],
                    "finding_partition_counts": {key: len(value) for key, value in verbose_partition.items()},
                    "retired_path_skip_reason_observed_in_registry": "semgrepignore_patterns_match",
                    "retired_finding_path_observation": retired["path_observation"],
                    "retired_finding_skip_hypothesis": retired["skip_hypothesis"],
                    "comparability": evaluation["comparability"],
                    "overall_assessment": evaluation["overall_assessment"],
                    "scope_completeness": scope.completeness_status.value,
                    "limitation_codes": sorted(evaluation["limitation_codes"]),
                },
                "same_scan_response_partition_across_modes": True,
                "invocation_modes_mixed_in_a_session": False,
                "released_session_reuse_status": unavailable.status_code,
                "source_or_token_output": False,
            }, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Avoid exception text that may contain paths, raw output, or request data.
        code = str(exc)
        allowed = {
            "python_version_mismatch", "semgrep_version_mismatch", "trusted_baseline_rules_unavailable",
            "scan_request_failed", "non_verbose_skip_reason_unexpectedly_public", "non_verbose_scope_unexpectedly_public", "unexpected_non_verbose_status", "unexpected_non_verbose_finding_partition",
            "run_handle_collision", "verbose_baseline_fixture_mismatch", "finding_partition_differs_between_modes",
            "verbose_partial_status_not_preserved", "session_binding_failed", "evaluation_failed",
            "baseline_only_finding_missing", "baseline_invocation_identity_mismatch",
            "current_invocation_identity_mismatch", "skip_evidence_not_observed", "scope_completeness_overstated",
            "partial_run_promoted_to_comparable", "skip_observation_projection_mismatch",
            "skip_hypothesis_projection_mismatch", "source_limitation_missing", "scope_limitation_missing",
            "sensitive_data_disclosed", "session_release_failed", "released_session_reused", "run_release_failed",
        }
        print(code if code in allowed else "er_d5_reproduction_failed", file=sys.stderr)
        raise SystemExit(1) from None
