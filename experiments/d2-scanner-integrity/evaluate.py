"""Score the saved D2 raw results against labels.json (PROTOCOL.md sections 4-8).

Usage: evaluate.py  (reads ./raw, writes ./results.json, prints a summary)
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
ARMS = ("a", "b", "c", "d_cli", "d_api", "d_inv")
PRODUCT = ("d_cli", "d_api", "d_inv")
ISSUE_CLASS = {
    "semgrep_skipped_paths": "SCOPE", "no_files_scanned": "SCOPE",
    "semgrep_skipped_rules": "RULE",
    "semgrep_timeout": "TIMEOUT",
    "invalid_json": "SCAN_FAILED", "nonzero_exit": "SCAN_FAILED", "semgrep_launch_failed": "SCAN_FAILED",
    "semgrep_failed": "SCAN_FAILED",
    "semgrep_reported_errors": "GENERIC", "evidence_unavailable": "GENERIC",
    "semgrep_output_limit": "OUTPUT", "findings_omitted": "OUTPUT",
}


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _reference_errors(case_dir: Path) -> list:
    document = _load(case_dir / "a.semgrep.json") or _load(case_dir / "a.semgrep.json.summary.json") or {}
    return document.get("errors") or []


def reason_classes(arm: str, verdict: dict) -> list[str]:
    if arm in ("a", "b"):
        return []
    if arm == "c":
        return list(verdict["reasons"])
    classes = {ISSUE_CLASS.get(issue, "GENERIC") for issue in verdict.get("issues", [])}
    if verdict.get("error") or (arm == "d_cli" and verdict.get("status") is None and verdict["verdict"] == "FLAG"):
        classes.add("SCAN_FAILED")  # settings rejected, service error, or CLI refused the input
    return sorted(classes)


def explain(label_reasons: list[str], classes: list[str]) -> str:
    specific = [item for item in classes if item != "GENERIC"]
    if any(item in label_reasons for item in specific):
        return "MATCH"
    if not specific:
        return "GENERIC"
    return "WRONG"


def fidelity(case_dir: Path) -> dict[str, dict[str, bool]]:
    a = _load(case_dir / "a.semgrep.json") or {}
    c = _load(case_dir / "arm_c.json") or {}
    cli = _load(case_dir / "d_cli.stdout.txt") or {}
    api = (_load(case_dir / "d_api.json") or {}).get("response") or {}
    a_paths = a.get("paths") if isinstance(a.get("paths"), dict) else {}
    stock = {
        "exit_code": False,
        "error_type_and_path": "errors" in a,
        "scanned_list": "scanned" in a_paths,
        "skipped_list_with_reason": "skipped" in a_paths,
        "rule_set_hash": False,
        "semgrep_version": "version" in a,
        "target_identity": False,
    }
    return {
        "a": stock, "b": dict(stock),
        "c": {
            "exit_code": "exit_code" in c, "error_type_and_path": "errors" in c, "scanned_list": "scanned" in c,
            "skipped_list_with_reason": "skipped" in c, "rule_set_hash": bool(c.get("rules_sha256")),
            "semgrep_version": bool(c.get("semgrep_version")), "target_identity": "target" in c,
        },
        "d_cli": {
            "exit_code": "exit_code" in cli.get("tool", {}), "error_type_and_path": False, "scanned_list": False,
            "skipped_list_with_reason": False, "rule_set_hash": False,
            "semgrep_version": bool(cli.get("tool", {}).get("version")), "target_identity": "id" in cli.get("target", {}),
        },
        "d_api": {
            "exit_code": "exit_code" in api, "error_type_and_path": False, "scanned_list": False,
            "skipped_list_with_reason": False, "rule_set_hash": False,
            "semgrep_version": bool(api.get("semgrep_version")), "target_identity": False,
        },
    }


def main() -> int:
    labels = _load(HERE / "labels.json")
    reps = sorted(path.name for path in RAW.iterdir() if path.is_dir())
    rows: list[dict] = []
    excluded: list[dict] = []
    for rep in reps:
        for case, spec in labels["cases"].items():
            case_dir = RAW / rep / case
            verdicts = _load(case_dir / "verdicts.json")
            complete, reasons = spec["complete"], spec.get("reason", [])
            if complete == "CONDITIONAL":
                if "timeout" in json.dumps(_reference_errors(case_dir)).lower():
                    complete, reasons = False, spec["if_reference_timeout"]["reason"]
                else:
                    excluded.append({"rep": rep, "case": case, "why": "reference scan reported no timeout error",
                                     "verdicts": {arm: verdicts[arm]["verdict"] for arm in ARMS}})
                    continue
            for arm in ARMS:
                verdict = verdicts[arm]
                classes = reason_classes(arm, verdict)
                flagged = verdict["verdict"] == "FLAG"
                rows.append({
                    "rep": rep, "case": case, "arm": arm, "label_complete": complete, "label_reasons": reasons,
                    "policy_dependent": spec["policy_dependent"], "verdict": verdict["verdict"],
                    "result_count": verdict.get("result_count"), "exit_code": verdict.get("exit_code"),
                    "status": verdict.get("status"), "classes": classes,
                    "miss": (not complete) and not flagged,
                    "false_block": complete and flagged,
                    "explanation": explain(reasons, classes) if (not complete and flagged) else None,
                })

    first = [row for row in rows if row["rep"] == reps[0]]
    summary: dict = {}
    for arm in ARMS:
        mine = [row for row in first if row["arm"] == arm]
        stable = True
        unstable = []
        for case in {row["case"] for row in rows}:
            seen = {(row["verdict"], tuple(row["classes"])) for row in rows if row["arm"] == arm and row["case"] == case}
            if len(seen) > 1:
                stable = False
                unstable.append(case)
        flagged_incomplete = [row for row in mine if row["explanation"]]
        summary[arm] = {
            "cases": len(mine),
            "incomplete_cases": sum(1 for row in mine if not row["label_complete"]),
            "complete_cases": sum(1 for row in mine if row["label_complete"]),
            "M1_missed": sorted(row["case"] for row in mine if row["miss"]),
            "M1_missed_non_policy": sorted(row["case"] for row in mine if row["miss"] and not row["policy_dependent"]),
            "M2_false_block": sorted(row["case"] for row in mine if row["false_block"]),
            "M3_explanation": {key: sum(1 for row in flagged_incomplete if row["explanation"] == key)
                               for key in ("MATCH", "GENERIC", "WRONG")},
            "reproducible": stable, "unstable": sorted(unstable),
        }
    best = min(PRODUCT, key=lambda arm: (len(summary[arm]["M1_missed"]) + len(summary[arm]["M2_false_block"]),
                                         len(summary[arm]["M1_missed"])))
    result = {
        "reps": reps, "excluded": excluded, "summary": summary, "product_best_mode": best,
        "per_case_first_rep": first,
        "evidence_fidelity_case_A": fidelity(RAW / reps[0] / "A"),
    }
    (HERE / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("reps", reps, "| excluded", [(item["rep"], item["case"]) for item in excluded], "| product best mode", best)
    for arm in ARMS:
        print(arm, json.dumps(summary[arm], sort_keys=True))
    print("\ncase | label | " + " | ".join(ARMS))
    for case in labels["cases"]:
        mine = [row for row in first if row["case"] == case]
        if not mine:
            print(case, "| EXCLUDED")
            continue
        label = "COMPLETE" if mine[0]["label_complete"] else "INCOMPLETE" + str(mine[0]["label_reasons"])
        cells = []
        for arm in ARMS:
            row = next(item for item in mine if item["arm"] == arm)
            mark = "MISS" if row["miss"] else "FALSE_BLOCK" if row["false_block"] else "ok"
            cells.append(f"{row['verdict']}{row['classes'] or ''} n={row['result_count']} {mark}")
        print(f"{case} | {label} | " + " | ".join(cells))
    for arm, items in result["evidence_fidelity_case_A"].items():
        print("fidelity", arm, sum(items.values()), [key for key, value in items.items() if value])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
