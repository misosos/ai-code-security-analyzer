#!/usr/bin/env python3
"""Reproduce ER-D2 projections from real Semgrep scans on synthetic JS."""

from __future__ import annotations

import json
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


def compare_projection(baseline: dict, current: dict, target_id: str, profile_id: str) -> dict:
    """Mirror compareScanSnapshots gates and Finding-ID set projection."""
    reasons: list[str] = []
    for label, scan in (("baseline", baseline), ("current", current)):
        if scan["scan_status"] != "completed" or scan["completed"] is not True:
            reasons.append(f"{label}_not_completed")
        if scan["omitted_finding_count"] != 0:
            reasons.append(f"{label}_findings_omitted")
        if scan["displayed_finding_count"] != len(scan["findings"]):
            reasons.append(f"{label}_count_inconsistent")
        if scan["finding_count"] != scan["displayed_finding_count"] + scan["omitted_finding_count"]:
            reasons.append(f"{label}_count_inconsistent")
        ids = [item["finding_id"] for item in scan["findings"]]
        if len(ids) != len(set(ids)):
            reasons.append(f"{label}_duplicate_finding_id")
    if target_id != "local-project":
        reasons.append("target_mismatch")
    if profile_id != "baseline":
        reasons.append("rule_profile_mismatch")
    if not baseline["semgrep_version"] or not current["semgrep_version"]:
        reasons.append("semgrep_version_unavailable")
    elif baseline["semgrep_version"] != current["semgrep_version"]:
        reasons.append("semgrep_version_mismatch")
    if reasons:
        return {"comparable": False, "reasons": reasons, "groups": None}

    base_by_id = {item["finding_id"]: item for item in baseline["findings"]}
    current_by_id = {item["finding_id"]: item for item in current["findings"]}
    ids_by_category = {
        "currentOnly": sorted(current_by_id.keys() - base_by_id.keys()),
        "shared": sorted(current_by_id.keys() & base_by_id.keys()),
        "baselineOnly": sorted(base_by_id.keys() - current_by_id.keys()),
    }
    paths = {
        finding["finding_id"]: finding["file_path"]
        for response in (baseline, current)
        for finding in response["findings"]
    }
    return {
        "comparable": True,
        "reasons": [],
        "groups": {
            category: sorted(paths[item] for item in ids if paths[item] is not None)
            for category, ids in ids_by_category.items()
        },
        "counts": {category: len(ids) for category, ids in ids_by_category.items()},
    }


def main() -> None:
    if sys.version_info[:3] != (3, 12, 7):
        raise RuntimeError("python_version_mismatch")
    semgrep = subprocess.run(
        ["semgrep", "--version"], capture_output=True, text=True, check=False, timeout=10
    )
    if semgrep.returncode != 0 or semgrep.stdout.strip() != "1.182.1":
        raise RuntimeError("semgrep_version_mismatch")

    repository = Path(__file__).resolve().parents[1]
    rules = (repository / "rules").resolve(strict=True)
    target = Path(tempfile.mkdtemp(prefix="er-d2-synthetic-")).resolve(strict=True)
    token = secrets.token_urlsafe(32)
    settings = ApiSettings(
        target,
        rules,
        token,
        allowed_hosts=("127.0.0.1",),
    )
    service = ScanService(settings)
    app = create_app(settings, scan_service=service, investigation_api_enabled=True)
    headers = {"X-Local-API-Token": token}
    request = {"target_id": "local-project", "rule_profile_id": "baseline"}
    created_handles: list[str] = []
    session_handle: str | None = None
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False, lifespan="off"))
    server_thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    server_thread.start()
    origin = f"http://127.0.0.1:{port}"

    try:
        (target / "stable.js").write_text(
            "function stable(input) { return eval(input); }\n", encoding="utf-8"
        )
        (target / "retired.js").write_text(
            "function retired(input) { return eval(input); }\n", encoding="utf-8"
        )

        deadline = time.monotonic() + 10
        while True:
            try:
                health = httpx.get(f"{origin}/api/v1/health", timeout=0.5, trust_env=False)
                assert health.status_code == 200
                break
            except (httpx.HTTPError, AssertionError):
                if time.monotonic() >= deadline or not server_thread.is_alive():
                    raise RuntimeError("isolated_api_server_unavailable") from None
                time.sleep(0.05)

        with httpx.Client(base_url=origin, headers=headers, timeout=60, trust_env=False) as client:
            baseline_response = client.post(
                "/api/v2/investigation-scans", json=request
            )
            assert baseline_response.status_code == 200
            baseline_envelope = baseline_response.json()
            assert baseline_envelope["scan"]["scan_status"] == "completed"
            created_handles.append(baseline_envelope["run_handle"])

            (target / "retired.js").write_text(
                "function retired(input) { return String(input); }\n", encoding="utf-8"
            )
            (target / "added.js").write_text(
                "function added(input) { return eval(input); }\n", encoding="utf-8"
            )
            current_response = client.post(
                "/api/v2/investigation-scans", json=request
            )
            assert current_response.status_code == 200
            current_envelope = current_response.json()
            assert current_envelope["scan"]["scan_status"] == "completed"
            created_handles.append(current_envelope["run_handle"])

            # Both methods receive the exact scan objects from these envelopes.
            baseline_scan = baseline_envelope["scan"]
            current_scan = current_envelope["scan"]
            comparison = compare_projection(
                baseline_scan,
                current_scan,
                target_id=request["target_id"],
                profile_id=request["rule_profile_id"],
            )
            assert comparison["comparable"] is True
            assert comparison["groups"] == {
                "currentOnly": ["added.js"],
                "shared": ["stable.js"],
                "baselineOnly": ["retired.js"],
            }

            same_run = client.post(
                "/api/v2/investigations",
                json={
                    "baseline_handle": created_handles[0],
                    "current_handle": created_handles[0],
                },
            )
            assert same_run.status_code == 409
            assert same_run.json() == {"error": "binding_rejected"}

            session_response = client.post(
                "/api/v2/investigations",
                json={
                    "baseline_handle": created_handles[0],
                    "current_handle": created_handles[1],
                },
            )
            assert session_response.status_code == 201
            session_handle = session_response.json()["investigation_handle"]

            evaluation_response = client.post(
                "/api/v2/investigations/evaluate",
                json={"investigation_handle": session_handle},
            )
            assert evaluation_response.status_code == 200
            evaluation = evaluation_response.json()

            finding_paths = {
                finding["finding_id"]: finding["file_path"]
                for scan in (baseline_scan, current_scan)
                for finding in scan["findings"]
            }
            evaluation_projection = {
                "contract_version": evaluation["contract_version"],
                "comparability": evaluation["comparability"],
                "overall_assessment": evaluation["overall_assessment"],
                "findings": sorted(
                    (
                        {
                            "file": finding_paths[item["finding_id"]],
                            "category": item["category"],
                            "path_observation": item["path_observation"],
                            "skip_hypothesis": item["skip_hypothesis"],
                            "source_snapshot_hypothesis": item["source_snapshot_hypothesis"],
                            "rule_identity_hypothesis": item["rule_identity_hypothesis"],
                        }
                        for item in evaluation["findings"]
                    ),
                    key=lambda item: (item["category"], item["file"]),
                ),
                "limitation_codes": sorted(evaluation["limitation_codes"]),
            }
            categories = {item["category"]: item["file"] for item in evaluation_projection["findings"]}
            assert categories == {
                "shared": "stable.js",
                "baselineOnly": "retired.js",
                "currentOnly": "added.js",
            }
            assert evaluation_projection["comparability"] == "COMPARABLE"
            assert evaluation_projection["overall_assessment"] == "UNDETERMINED"

            # This is an internal inspection of the exact Registry-bound Manifest;
            # only the bounded status, never its payload or identifiers, is emitted.
            current_bundle = app.state.investigation_registry.get_run(created_handles[1])
            skip_status = current_bundle.manifest.scope_evidence.skipped_status.value
            # ER-D4's investigation-only --verbose invocation now exposes the
            # bounded skip collection status. This historical code-path
            # scenario scans retired.js, so the path is reported scanned and
            # does not imply a skip or code-change cause.
            assert skip_status == "OBSERVED"
            retired = next(
                item for item in evaluation_projection["findings"]
                if item["category"] == "baselineOnly"
            )
            assert retired["path_observation"] == "PATH_REPORTED_SCANNED"
            assert retired["skip_hypothesis"] == "CONTRADICTED"

            release_session = client.post(
                "/api/v2/investigation-release",
                json={"kind": "investigation", "handle": session_handle},
            )
            assert release_session.status_code == 204
            released_evaluation = client.post(
                "/api/v2/investigations/evaluate",
                json={"investigation_handle": session_handle},
            )
            assert released_evaluation.status_code == 404
            assert released_evaluation.json() == {"error": "evidence_unavailable"}

            print(
                json.dumps(
                    {
                        "scenario_01_same_response_projection": comparison,
                        "scenario_01_evaluation_projection": evaluation_projection,
                        "scenario_02_evidence_gap": {
                            "current_manifest_skip_status": skip_status,
                            "retired_path_observation": retired["path_observation"],
                            "skip_hypothesis": retired["skip_hypothesis"],
                            "source_snapshot_not_collected": "source_snapshot_not_collected"
                            in evaluation["limitation_codes"],
                            "rule_bytes_unverified": "rule_bytes_unverified"
                            in evaluation["limitation_codes"],
                            "loaded_rule_identity_unverified": "loaded_rule_identity_unverified"
                            in evaluation["limitation_codes"],
                            "scope_completeness_unverified": "scope_completeness_unverified"
                            in evaluation["limitation_codes"],
                        },
                        "scenario_03_same_run_rejected": {
                            "status": same_run.status_code,
                            "error": same_run.json()["error"],
                        },
                        "released_session_reuse_rejected": {
                            "status": released_evaluation.status_code,
                            "error": released_evaluation.json()["error"],
                        },
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)
        listener.close()
        registry = app.state.investigation_registry
        if session_handle is not None:
            try:
                registry.release_session(session_handle)
            except Exception:
                pass
        for handle in created_handles:
            try:
                registry.release_run(handle)
            except Exception:
                pass
        # Remove only this harness-owned, randomly named synthetic directory.
        import shutil

        shutil.rmtree(target)


if __name__ == "__main__":
    main()
