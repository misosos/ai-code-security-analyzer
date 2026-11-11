"""Run one D2 case once through Arms A, B, C and the three product modes.

Usage: run_case.py CASE REP TMP_ROOT OUT_ROOT

Run with the product package on PYTHONPATH (this worktree's ``src``). Synthetic
targets are only scanned by Semgrep; no target code is executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_cases  # noqa: E402
import integrity_check  # noqa: E402

from ai_code_security_analyzer.services.scan_service import (  # noqa: E402
    ApiSettings, ProjectTarget, ScanService, ServiceError,
)

SEMGREP_VERSION = "1.182.1"
COMMON = ["--json", "--metrics=off", "--disable-version-check", "--oss-only", "--no-autofix"]
LARGE = 300_000


def _env(home: str) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": home, "XDG_CACHE_HOME": home,
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}


def semgrep(rules_dir: Path, target: Path, extra: list[str]) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory(prefix="d2-home-") as home:
        done = subprocess.run(
            ["semgrep", "scan", *COMMON, *extra, "--config", build_cases.RULE_FILE, "--", str(target)],
            cwd=rules_dir, env=_env(home), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    return done.returncode, done.stdout, done.stderr


def product_cli(rules_dir: Path, target: Path) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory(prefix="d2-home-") as home:
        env = _env(home) | {"PYTHONPATH": os.environ.get("PYTHONPATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        done = subprocess.run(
            [sys.executable, "-m", "ai_code_security_analyzer", "scan", "--path", str(target),
             "--rules", str(rules_dir / build_cases.RULE_FILE), "--format", "json"],
            cwd=home, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    return done.returncode, done.stdout, done.stderr


def product_service(rules_dir: Path, target: Path, *, verbose: bool) -> dict:
    try:
        settings = ApiSettings(target_directory=None, trusted_rules_directory=rules_dir, api_token="A" * 43,
                               project_targets=(ProjectTarget("d2", "d2", target),))
    except (ValueError, OSError) as error:
        return {"verdict": "FLAG", "error": f"settings_rejected:{error}", "issues": []}
    service = ScanService(settings)
    try:
        if verbose:
            response, _manifest = service._scan_with_manifest("d2", "baseline", investigation_verbose=True)
        else:
            response = service.scan("d2", "baseline")
    except ServiceError as error:
        return {"verdict": "FLAG", "error": f"service:{error.status_code}:{error.code}", "issues": []}
    dumped = response.model_dump(mode="json")
    issues = list(dumped["issues"])
    dumped["findings"] = dumped["findings"][:3]  # keep the saved artifact small; counts stay intact
    return {"verdict": "PASS" if dumped["completed"] and not issues else "FLAG", "issues": issues,
            "response": dumped}


def main() -> int:
    case, rep, tmp_root, out_root = sys.argv[1], sys.argv[2], Path(sys.argv[3]).resolve(), Path(sys.argv[4])
    version = subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
    if version != SEMGREP_VERSION:
        raise SystemExit(f"semgrep version mismatch: {version}")
    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    intent = labels["default_intent"] | labels["cases"][case].get("intent", {})
    expected_sha = labels["production_rules_sha256"] if intent["expected_rules"] == "production" else None

    root = tmp_root / f"run{rep}" / case
    if root.exists():
        shutil.rmtree(root)
    built = build_cases.build(case, root, HERE.parents[1] / "rules")
    repo, target, rules_dir = built["repo"], built["target"], built["rules_dir"]
    out = out_root / f"run{rep}" / case
    out.mkdir(parents=True, exist_ok=True)

    def clean(text: str) -> str:
        return text.replace(str(tmp_root), "<TMP>").replace(str(tmp_root).removeprefix("/private"), "<TMP>")

    def save(name: str, text: str) -> None:
        text = clean(text)
        if len(text) > LARGE:
            summary: dict = {"omitted_large_output": True, "bytes": len(text.encode("utf-8")),
                             "sha256_of_sanitized_text": hashlib.sha256(text.encode("utf-8")).hexdigest()}
            try:
                document = json.loads(text)
                summary |= {"version": document.get("version"), "result_count": len(document.get("results", [])),
                            "errors": document.get("errors"), "paths": document.get("paths"),
                            "skipped_rules": document.get("skipped_rules")}
            except ValueError:
                summary["head"] = text[:2000]
            name, text = name + ".summary.json", json.dumps(summary, indent=2, sort_keys=True)
        (out / name).write_text(text, encoding="utf-8")

    a = semgrep(rules_dir, target, [])
    b = semgrep(rules_dir, target, ["--strict"])
    c = semgrep(rules_dir, target, ["--verbose"])
    report_c = integrity_check.check(c[1], c[0], target, repo, rules_dir / build_cases.RULE_FILE, expected_sha)
    cli = product_cli(rules_dir, target)
    api = product_service(rules_dir, target, verbose=False)
    inv = product_service(rules_dir, target, verbose=True)

    try:
        cli_report = json.loads(cli[1])
        cli_issues = list(cli_report.get("issues", []))
    except ValueError:
        cli_report, cli_issues = None, []

    def count(text: str) -> int | None:
        try:
            return len(json.loads(text)["results"])
        except (ValueError, KeyError, TypeError):
            return None

    verdicts = {
        "case": case, "rep": int(rep), "semgrep": version,
        "a": {"verdict": "PASS" if a[0] == 0 else "FLAG", "exit_code": a[0], "result_count": count(a[1]), "reasons": []},
        "b": {"verdict": "PASS" if b[0] == 0 else "FLAG", "exit_code": b[0], "result_count": count(b[1]), "reasons": []},
        "c": {"verdict": report_c["verdict"], "exit_code": c[0], "result_count": count(c[1]),
              "reasons": sorted({item["class"] for item in report_c["reasons"]})},
        "d_cli": {"verdict": "PASS" if cli[0] == 0 else "FLAG", "exit_code": cli[0], "issues": cli_issues,
                  "status": (cli_report or {}).get("status"),
                  "result_count": (cli_report or {}).get("summary", {}).get("finding_count")},
        "d_api": {"verdict": api["verdict"], "issues": api["issues"], "error": api.get("error"),
                  "status": (api.get("response") or {}).get("scan_status"),
                  "result_count": (api.get("response") or {}).get("finding_count")},
        "d_inv": {"verdict": inv["verdict"], "issues": inv["issues"], "error": inv.get("error"),
                  "status": (inv.get("response") or {}).get("scan_status"),
                  "result_count": (inv.get("response") or {}).get("finding_count")},
    }

    save("a.semgrep.json", a[1]); save("a.stderr.txt", a[2])
    save("b.semgrep.json", b[1]); save("b.stderr.txt", b[2])
    save("c.semgrep.json", c[1]); save("c.stderr.txt", c[2])
    save("arm_c.json", json.dumps(report_c, indent=2, sort_keys=True))
    save("d_cli.stdout.txt", cli[1]); save("d_cli.stderr.txt", cli[2])
    save("d_api.json", json.dumps(api, indent=2, sort_keys=True))
    save("d_inv.json", json.dumps(inv, indent=2, sort_keys=True))
    save("verdicts.json", json.dumps(verdicts, indent=2, sort_keys=True))
    shutil.rmtree(root)
    print(f"done {case} rep{rep}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
