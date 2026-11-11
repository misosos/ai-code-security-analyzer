"""Run one D1 case once through Arms A, B and C and save sanitized raw results.

Usage: run_case.py CASE REP TMP_ROOT OUT_ROOT

Run with the product package on PYTHONPATH (this worktree's ``src``). Synthetic
targets are only scanned by Semgrep; no target code is executed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import baseline_b  # noqa: E402
import build_cases  # noqa: E402

from ai_code_security_analyzer.investigation_evidence_registry import (  # noqa: E402
    EvidenceRegistryError, RunEvidenceRegistry,
)
from ai_code_security_analyzer.services.scan_service import (  # noqa: E402
    ApiSettings, ProjectTarget, ScanService, ServiceError,
)

SEMGREP_VERSION = "1.182.1"
COMMON = ["--json", "--metrics=off", "--disable-version-check", "--oss-only", "--no-autofix"]


def _env(home: str) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": home, "XDG_CACHE_HOME": home,
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}


def semgrep(rules_dir: Path, repo: Path, *, verbose: bool) -> tuple[int, str]:
    """Stock scan: cwd is the rules directory so check_id stays the bare rule id."""
    with tempfile.TemporaryDirectory(prefix="d1-home-") as home:
        args = ["semgrep", "scan", *COMMON, "--config", build_cases.RULE_FILE]
        if verbose:
            args.append("--verbose")
        done = subprocess.run([*args, "--", str(repo)], cwd=rules_dir, env=_env(home),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
    return done.returncode, done.stdout


def semgrep_baseline_commit(rules_dir: Path, repo: Path, base_sha: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="d1-home-") as home:
        env = _env(home) | {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        done = subprocess.run(
            ["semgrep", "scan", *COMMON, "--config", str(rules_dir / build_cases.RULE_FILE),
             "--baseline-commit", base_sha, "--", "."],
            cwd=repo, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
    return done.returncode, done.stdout


def _results(text: str, repo: Path) -> list[dict] | None:
    try:
        document = json.loads(text)
        return [{"check_id": item["check_id"], "path": baseline_b._rel(item["path"], repo),
                 "line": item["start"]["line"], "col": item["start"]["col"],
                 "end_line": item["end"]["line"], "end_col": item["end"]["col"]}
                for item in document["results"]]
    except (ValueError, KeyError, TypeError):
        return None


def arm_a(base: tuple[int, str], cur: tuple[int, str], repo: Path) -> dict:
    base_results, cur_results = _results(base[1], repo), _results(cur[1], repo)
    out = {"exit_codes": {"base": base[0], "current": cur[0]}, "findings": []}
    valid = base_results is not None and cur_results is not None and cur[0] == 0 and base[0] == 0
    identity = lambda item: (item["check_id"], item["path"], item["line"], item["col"], item["end_line"], item["end_col"])
    current = {identity(item) for item in cur_results or []}
    for item in base_results or []:
        if not valid:
            presence = "NO_VALID_COMPARISON"
        else:
            presence = "STILL_PRESENT" if identity(item) in current else "DISAPPEARED"
        out["findings"].append({"path": item["path"], "line": item["line"], "presence": presence,
                                "causes": [], "fix_claim": False})
    out["current_only_count"] = len(current - {identity(item) for item in base_results or []}) if valid else None
    return out


def _dump(value) -> object:
    return json.loads(json.dumps(value, default=str))


class ProductArm:
    """Arm C: the real service, evaluator and registry, in process, without HTTP."""

    MODES = ("verbose", "standard", "rule_bytes")

    def __init__(self, repo: Path, rules_dir: Path) -> None:
        settings = ApiSettings(target_directory=None, trusted_rules_directory=rules_dir, api_token="A" * 43,
                               project_targets=(ProjectTarget("d1", "d1", repo),))
        self.service = ScanService(settings)
        self.registries = {mode: RunEvidenceRegistry() for mode in self.MODES}
        self.runs: dict[str, dict[str, dict]] = {mode: {} for mode in self.MODES}

    def scan(self, state: str) -> None:
        for mode in self.MODES:
            record: dict = {}
            try:
                if mode == "rule_bytes":
                    response, manifest, observation = self.service._scan_with_rule_bytes_manifest("d1", "baseline")
                    handle = self.registries[mode].register_rule_bytes_run(response, manifest, observation)
                else:
                    response, manifest = self.service._scan_with_manifest(
                        "d1", "baseline", investigation_verbose=(mode == "verbose"))
                    handle = self.registries[mode].register_run(response, manifest)
                scope = manifest.scope_evidence
                record = {
                    "response": _dump(response.model_dump(mode="json")),
                    "scope": {"scanned_status": str(scope.scanned_status), "scanned_paths": list(scope.scanned_paths),
                              "skipped_status": str(scope.skipped_status),
                              "skipped_paths": [[item.path, item.reason_code] for item in scope.skipped_paths],
                              "errors_count": scope.errors_count, "limitations": list(scope.limitations)},
                    "_handle": handle,
                }
            except ServiceError as error:
                record = {"error": f"service:{error.status_code}:{error.code}"}
            except EvidenceRegistryError as error:
                record = {"error": f"registry:{error.code}"}
            self.runs[mode][state] = record

    def evaluate(self) -> dict:
        out: dict = {"modes": {}}
        for mode in self.MODES:
            base, cur = self.runs[mode]["base"], self.runs[mode]["cur"]
            entry: dict = {"base": {k: v for k, v in base.items() if k != "_handle"},
                           "cur": {k: v for k, v in cur.items() if k != "_handle"}}
            if "_handle" in base and "_handle" in cur:
                registry = self.registries[mode]
                try:
                    session = registry.create_session(base["_handle"], cur["_handle"])
                    entry["evaluation"] = _dump(asdict(registry.evaluate(session)))
                    if mode == "rule_bytes":
                        entry["rule_bytes"] = _dump(asdict(registry.evaluate_rule_bytes(session)))
                except EvidenceRegistryError as error:
                    entry["evaluation_error"] = f"registry:{error.code}"
            else:
                entry["evaluation_error"] = "run_evidence_missing"
            out["modes"][mode] = entry
        out["findings"], out["current_only_count"], out["partition_mode"] = self._normalize(out["modes"])
        return out

    def _normalize(self, modes: dict) -> tuple[list[dict], int | None, str | None]:
        """PROTOCOL.md Arm C table: first valid partition, union of per-mode observations."""
        base_findings = None
        for mode in self.MODES:
            response = modes[mode]["base"].get("response")
            if response:
                base_findings = response["findings"]
                break
        if base_findings is None:
            return [], None, None
        partition, partition_mode = None, None
        for mode in self.MODES:
            evaluation = modes[mode].get("evaluation")
            if evaluation and evaluation["findings"]:
                partition = {item["finding_id"]: item for item in evaluation["findings"]}
                partition_mode = mode
                break
            if evaluation and evaluation["comparability"] == "COMPARABLE":
                partition, partition_mode = {}, mode
                break
        skip_supported: set[str] = set()
        for mode in self.MODES:
            for item in (modes[mode].get("evaluation") or {}).get("findings", []):
                if item.get("skip_hypothesis") == "SUPPORTED":
                    skip_supported.add(item["finding_id"])
        rule_changed = (modes["rule_bytes"].get("rule_bytes") or {}).get("status") == "DIFFERENT_SELECTED_BYTES"
        findings = []
        for item in base_findings:
            row = {"path": item["file_path"], "line": item["line_number"], "causes": [], "fix_claim": False}
            category = (partition or {}).get(item["finding_id"], {}).get("category") if partition is not None else None
            if category == "shared":
                row["presence"] = "STILL_PRESENT"
            elif category == "baselineOnly":
                row["presence"] = "DISAPPEARED"
                if item["finding_id"] in skip_supported:
                    row["causes"].append("SCOPE_EXCLUDED")
                if rule_changed:
                    row["causes"].append("RULE_FILE_CHANGED")
            else:
                row["presence"] = "NO_VALID_COMPARISON"
            findings.append(row)
        current_only = sum(1 for item in (partition or {}).values() if item["category"] == "currentOnly") \
            if partition is not None else None
        return findings, current_only, partition_mode


def main() -> int:
    case, rep, tmp_root, out_root = sys.argv[1], sys.argv[2], Path(sys.argv[3]).resolve(), Path(sys.argv[4])
    version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
    if version != SEMGREP_VERSION:
        raise SystemExit(f"semgrep version mismatch: {version}")
    root = tmp_root / f"run{rep}" / case
    if root.exists():
        shutil.rmtree(root)
    repo, rules_dir, keep = root / "repo", root / "rules", root / "keep"
    keep.mkdir(parents=True)
    production_rules = HERE.parents[1] / "rules"
    out = out_root / f"run{rep}" / case
    out.mkdir(parents=True, exist_ok=True)

    def save(name: str, text: str) -> None:
        clean = text.replace(str(tmp_root), "<TMP>").replace(str(tmp_root).removeprefix("/private"), "<TMP>")
        (out / name).write_text(clean, encoding="utf-8")

    base_sha = build_cases.build_base(case, repo, rules_dir, production_rules)
    product = ProductArm(repo, rules_dir)
    shutil.copyfile(rules_dir / build_cases.RULE_FILE, keep / "rules_base.yml")
    a_base = semgrep(rules_dir, repo, verbose=False)
    b_base = semgrep(rules_dir, repo, verbose=True)
    (keep / "b_base.json").write_text(b_base[1], encoding="utf-8")
    product.scan("base")

    cur_sha = build_cases.apply_change(case, repo, rules_dir)
    shutil.copyfile(rules_dir / build_cases.RULE_FILE, keep / "rules_cur.yml")
    a_cur = semgrep(rules_dir, repo, verbose=False)
    b_cur = semgrep(rules_dir, repo, verbose=True)
    (keep / "b_cur.json").write_text(b_cur[1], encoding="utf-8")
    a_baseline = semgrep_baseline_commit(rules_dir, repo, base_sha)
    product.scan("cur")

    report_b = baseline_b.compare(repo, base_sha, keep / "b_base.json", keep / "b_cur.json",
                                  b_base[0], b_cur[0], keep / "rules_base.yml", keep / "rules_cur.yml")
    report_a = arm_a(a_base, a_cur, repo)
    baseline_results = _results(a_baseline[1], repo)
    report_a["baseline_commit"] = {"exit_code": a_baseline[0], "results": baseline_results}
    report_c = product.evaluate()

    save("a_base.semgrep.json", a_base[1])
    save("a_cur.semgrep.json", a_cur[1])
    save("a_baseline_commit.semgrep.json", a_baseline[1])
    save("b_base.semgrep.json", b_base[1])
    save("b_cur.semgrep.json", b_cur[1])
    save("arm_a.json", json.dumps(report_a, indent=2, sort_keys=True))
    save("arm_b.json", json.dumps(report_b, indent=2, sort_keys=True))
    save("arm_c.json", json.dumps(report_c, indent=2, sort_keys=True))
    save("meta.json", json.dumps({"case": case, "rep": int(rep), "semgrep": version,
                                  "base_sha": base_sha, "cur_sha": cur_sha}, indent=2, sort_keys=True))
    shutil.rmtree(root)
    print(f"done {case} rep{rep}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
