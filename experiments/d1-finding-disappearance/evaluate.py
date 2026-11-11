"""Score the saved D1 raw results against labels.json (PROTOCOL.md sections 6-10).

Usage: evaluate.py  (reads ./raw, writes ./results.json, prints a summary)
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
RULE = "baseline.javascript-dynamic-eval"
ARMS = ("a", "b", "c")


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _has(document, path: str, line: int) -> bool:
    if not isinstance(document, dict):
        return False
    for item in document.get("results", []):
        item_path = item["path"]
        if item["check_id"] == RULE and item["start"]["line"] == line and (
                item_path == path or item_path.endswith("/" + path)):
            return True
    return False


def _split(key: str) -> tuple[str, int]:
    path, line = key.rsplit(":", 1)
    return path, int(line)


def score(label_fate: str, label_causes: list[str], row: dict | None, coarse: dict[str, str]) -> str:
    if row is None:
        return "NONE"
    presence, causes = row["presence"], row["causes"]
    if label_fate == "PERSISTS":
        return {"STILL_PRESENT": "EXACT", "DISAPPEARED": "WRONG"}.get(presence, "NONE")
    if presence == "STILL_PRESENT":
        return "WRONG"
    if presence == "NO_VALID_COMPARISON":
        return "EXACT" if set(label_causes) == {"SCAN_INCOMPLETE"} else "NONE"
    if not causes:
        return "NONE"
    if set(causes) == set(label_causes):
        return "EXACT"
    got = {coarse[item] for item in causes}
    want = {coarse[item] for item in label_causes}
    if got == want:
        return "COARSE"
    if got < want:
        return "PARTIAL"
    return "WRONG"


def evidence_fidelity(case_dir: Path) -> dict[str, dict[str, bool]]:
    """M5: what each arm's own persisted artifact contains (seven fixed items)."""
    a_cur, a_base = _load(case_dir / "a_cur.semgrep.json") or {}, _load(case_dir / "a_base.semgrep.json") or {}
    arm_b = _load(case_dir / "arm_b.json") or {}
    arm_c = _load(case_dir / "arm_c.json") or {}
    a_lines = [item.get("extra", {}).get("lines") for item in a_base.get("results", [])]
    a_paths = a_base.get("paths", {}) if isinstance(a_base.get("paths"), dict) else {}
    public_c = [mode[state].get("response", {}) for mode in arm_c.get("modes", {}).values() for state in ("base", "cur")]
    public_c_eval = [mode.get("evaluation", {}) for mode in arm_c.get("modes", {}).values()]
    blob_c = json.dumps([public_c, public_c_eval])
    return {
        "a": {
            "semgrep_version": "version" in a_base,
            "exit_code": False,
            "rule_file_hash": False,
            "git_commit": False,
            "scanned_and_skipped_paths": "scanned" in a_paths and "skipped" in a_paths,
            "match_content_or_hash": bool(a_lines) and all(item not in (None, "requires login") for item in a_lines),
            "raw_or_digest": bool(a_base) or bool(a_cur),
        },
        "b": {
            "semgrep_version": bool(arm_b.get("semgrep_version", {}).get("base")),
            "exit_code": "exit_codes" in arm_b,
            "rule_file_hash": "rule_file_sha256" in arm_b,
            "git_commit": bool(arm_b.get("git", {}).get("base")),
            "scanned_and_skipped_paths": "scope" in arm_b,
            "match_content_or_hash": any("match_sha256" in item for item in arm_b.get("findings", [])),
            "raw_or_digest": "raw_sha256" in arm_b,
        },
        "c": {
            "semgrep_version": any(item.get("semgrep_version") for item in public_c),
            "exit_code": '"exit_code"' in blob_c,
            "rule_file_hash": "sha256" in blob_c,
            "git_commit": '"git' in blob_c or "commit" in blob_c,
            "scanned_and_skipped_paths": "scanned_paths" in blob_c,
            "match_content_or_hash": "match_sha256" in blob_c or '"lines"' in blob_c,
            "raw_or_digest": False,
        },
    }


def main() -> int:
    labels = _load(HERE / "labels.json")
    coarse = dict(labels["coarse"]) | {"RULE_FILE_CHANGED": "RULE"}
    reps = sorted(path.name for path in RAW.iterdir() if path.is_dir())
    rows: list[dict] = []
    excluded: list[dict] = []
    extras: dict = {}
    fidelity: dict = {}
    for rep in reps:
        for case, spec in labels["cases"].items():
            case_dir = RAW / rep / case
            ref_base, ref_cur = _load(case_dir / "a_base.semgrep.json"), _load(case_dir / "a_cur.semgrep.json")
            arms = {arm: _load(case_dir / f"arm_{arm}.json") or {"findings": []} for arm in ARMS}
            missing = [f["key"] for f in spec["findings"] if not _has(ref_base, *_split(f["key"]))]
            if missing:
                excluded.append({"rep": rep, "case": case, "missing_base_findings": missing})
                continue
            extras[f"{rep}/{case}"] = {
                "a_current_only": arms["a"].get("current_only_count"),
                "c_current_only": arms["c"].get("current_only_count"),
                "c_partition_mode": arms["c"].get("partition_mode"),
                "baseline_commit": arms["a"].get("baseline_commit"),
                "a_exit": arms["a"].get("exit_codes"),
                "c_overall": {mode: (value.get("evaluation") or {}).get("overall_assessment")
                              or value.get("evaluation_error")
                              for mode, value in arms["c"].get("modes", {}).items()},
                "c_scan_status": {mode: [value[state].get("response", {}).get("scan_status") or value[state].get("error")
                                         for state in ("base", "cur")]
                                  for mode, value in arms["c"].get("modes", {}).items()},
                "c_rule_bytes": ((arms["c"].get("modes", {}).get("rule_bytes") or {}).get("rule_bytes") or {}).get("status"),
            }
            if rep == reps[0]:
                fidelity[case] = evidence_fidelity(case_dir)
            for finding in spec["findings"]:
                path, line = _split(finding["key"])
                fate, causes = finding["fate"], finding.get("causes", [])
                conditional = fate == "CONDITIONAL"
                if conditional:
                    branch = finding["if_reference_reports"] if _has(ref_cur, path, line) else finding["if_reference_absent"]
                    fate, causes = branch["fate"], branch["causes"]
                for arm in ARMS:
                    row = next((item for item in arms[arm]["findings"]
                                if item["path"] == path and item["line"] == line), None)
                    rows.append({
                        "rep": rep, "case": case, "key": finding["key"], "arm": arm,
                        "label_fate": fate, "label_causes": causes, "conditional": conditional,
                        "dangerous_after": finding["dangerous_code_present_after"],
                        "determinable": finding["determinable"],
                        "presence": row["presence"] if row else "ARM_BASE_MISSING",
                        "causes": row["causes"] if row else [],
                        "fix_claim": bool(row and row["fix_claim"]),
                        "score": score(fate, causes, row, coarse),
                    })

    summary: dict = {}
    for arm in ARMS:
        mine = [row for row in rows if row["arm"] == arm]
        first = [row for row in mine if row["rep"] == reps[0]]
        verdict = lambda row: (row["presence"], tuple(row["causes"]), row["fix_claim"])
        by_key: dict = {}
        for row in mine:
            by_key.setdefault((row["case"], row["key"]), set()).add(verdict(row))
        unstable = sorted(f"{case}:{key}" for (case, key), values in by_key.items() if len(values) > 1)
        counts = Counter(row["score"] for row in first)
        n = len(first)
        determinable = [row for row in first if row["determinable"]]
        undeterminable = [row for row in first if not row["determinable"]]
        hold = lambda row: row["presence"] == "NO_VALID_COMPARISON" or (row["presence"] == "DISAPPEARED" and not row["causes"])
        disappeared = [row for row in first if row["label_fate"] == "NOT_REPORTED" and row["presence"] == "DISAPPEARED"]
        summary[arm] = {
            "n": n,
            "scores": dict(counts),
            "exact_or_coarse_rate": round((counts["EXACT"] + counts["COARSE"]) / n, 4) if n else None,
            "M1_false_fix_claims": sum(1 for row in first if row["fix_claim"] and row["dangerous_after"]),
            "M3a_correct_hold": [sum(1 for row in undeterminable if hold(row)), len(undeterminable)],
            "M3b_no_fix_claim_on_disappeared": [sum(1 for row in disappeared if not row["fix_claim"]), len(disappeared)],
            "M4_unnecessary_hold": [sum(1 for row in determinable if row["score"] == "NONE"), len(determinable)],
            "naive_reading_exposure": sum(1 for row in first if row["presence"] == "DISAPPEARED"
                                          and not row["causes"] and row["dangerous_after"]),
            "false_disappearance": sum(1 for row in first if row["label_fate"] == "PERSISTS" and row["presence"] == "DISAPPEARED"),
            "reproducible_across_reps": not unstable,
            "unstable": unstable,
        }
    result = {"reps": reps, "excluded": excluded, "summary": summary,
              "per_finding_first_rep": [row for row in rows if row["rep"] == reps[0]],
              "extras_first_rep": {key: value for key, value in extras.items() if key.startswith(reps[0])},
              "evidence_fidelity_first_rep": fidelity}
    (HERE / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("reps", reps, "excluded", excluded)
    for arm in ARMS:
        print(arm, json.dumps(summary[arm], sort_keys=True))
    print("\ncase | finding | label | A | B | C")
    first = result["per_finding_first_rep"]
    keys = []
    for row in first:
        if (row["case"], row["key"]) not in keys:
            keys.append((row["case"], row["key"]))
    for case, key in keys:
        cells = []
        for arm in ARMS:
            row = next(item for item in first if item["case"] == case and item["key"] == key and item["arm"] == arm)
            cells.append(f"{row['presence']}{row['causes'] or ''} => {row['score']}")
        label = next(item for item in first if item["case"] == case and item["key"] == key)
        print(f"{case} | {key} | {label['label_fate']}{label['label_causes'] or ''}{' (cond)' if label['conditional'] else ''} | "
              + " | ".join(cells))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
