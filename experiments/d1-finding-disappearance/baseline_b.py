"""Arm B: a reasonable Semgrep JSON + git comparison script (stdlib + git only).

Implements PROTOCOL.md section 5 "Arm B" rules 1-7. It never claims a fix.

Usage:
  baseline_b.py --repo DIR --base-sha SHA --base-json F --cur-json F \
      --base-exit N --cur-exit N --base-rules F --cur-rules F
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": tempfile.gettempdir(),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", *args], cwd=repo, env=env, check=check, capture_output=True, text=True)


def _rel(path: str, repo: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(repo).as_posix()
        except ValueError:
            return path
    return candidate.as_posix()


def _load(path: Path) -> dict | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        return None
    return document


def _findings(document: dict, repo: Path) -> list[dict]:
    out = []
    for item in document["results"]:
        out.append({
            "check_id": item["check_id"], "path": _rel(item["path"], repo),
            "line": item["start"]["line"], "end_line": item["end"]["line"],
        })
    return out


def _rule_block(text: str, rule_id: str) -> str | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)- id:\s*(\S+)\s*$", line)
        if match and match.group(2) == rule_id:
            indent = match.group(1)
            end = len(lines)
            for later in range(index + 1, len(lines)):
                if re.match(rf"^{re.escape(indent)}- id:\s", lines[later]):
                    end = later
                    break
            return "\n".join(lines[index:end]).rstrip()
    return None


def _hunks(old_text: str, new_text: str) -> list[tuple[int, int, int, int]]:
    """Return (old_start, old_count, new_start, new_count) from git diff -U0."""
    with tempfile.TemporaryDirectory() as temporary:
        old, new = Path(temporary) / "old", Path(temporary) / "new"
        old.write_text(old_text, encoding="utf-8")
        new.write_text(new_text, encoding="utf-8")
        done = _git(Path(temporary), "diff", "--no-index", "-U0", "--", "old", "new", check=False)
    hunks = []
    for line in done.stdout.splitlines():
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
        if match:
            hunks.append((int(match.group(1)), int(match.group(2) or 1),
                          int(match.group(3)), int(match.group(4) or 1)))
    return hunks


def _map_line(line: int, hunks: list[tuple[int, int, int, int]]) -> int | None:
    """Map an old line to its new line; None when the line itself was changed or deleted."""
    offset = 0
    for old_start, old_count, _new_start, new_count in hunks:
        if old_count > 0 and old_start <= line <= old_start + old_count - 1:
            return None
        before = (old_start + old_count - 1 < line) if old_count > 0 else (old_start < line)
        if before:
            offset += new_count - old_count
    return line + offset


def compare(repo: Path, base_sha: str, base_json: Path, cur_json: Path, base_exit: int, cur_exit: int,
            base_rules: Path, cur_rules: Path) -> dict:
    repo = repo.resolve()
    base_doc, cur_doc = _load(base_json), _load(cur_json)
    base_rule_text = base_rules.read_text(encoding="utf-8")
    cur_rule_text = cur_rules.read_text(encoding="utf-8")
    report: dict = {
        "tool": "d1-baseline-b/v1",
        "git": {"base": base_sha, "current": _git(repo, "rev-parse", "HEAD").stdout.strip()},
        "semgrep_version": {"base": (base_doc or {}).get("version"), "current": (cur_doc or {}).get("version")},
        "exit_codes": {"base": base_exit, "current": cur_exit},
        "rule_file_sha256": {"base": hashlib.sha256(base_rule_text.encode()).hexdigest(),
                             "current": hashlib.sha256(cur_rule_text.encode()).hexdigest()},
        "raw_sha256": {"base": hashlib.sha256(base_json.read_bytes()).hexdigest() if base_json.exists() else None,
                       "current": hashlib.sha256(cur_json.read_bytes()).hexdigest() if cur_json.exists() else None},
        "findings": [],
    }
    base_findings = _findings(base_doc, repo) if base_doc else []

    # Rule 1: scan validity.
    reasons = []
    if base_doc is None:
        reasons.append("base_json_invalid")
    if cur_doc is None:
        reasons.append("current_json_invalid")
    if base_exit != 0:
        reasons.append("base_exit_nonzero")
    if cur_exit != 0:
        reasons.append("current_exit_nonzero")
    if reasons:
        report["comparison"] = {"valid": False, "reasons": reasons}
        for item in base_findings:
            report["findings"].append({**item, "presence": "NO_VALID_COMPARISON", "causes": [], "fix_claim": False})
        return report
    report["comparison"] = {"valid": True, "reasons": []}

    paths = cur_doc.get("paths") if isinstance(cur_doc.get("paths"), dict) else {}
    scanned = {_rel(item, repo) for item in paths.get("scanned", []) if isinstance(item, str)}
    skipped = {_rel(item["path"], repo): item.get("reason") for item in paths.get("skipped", [])
               if isinstance(item, dict) and isinstance(item.get("path"), str)}
    report["scope"] = {"scanned": sorted(scanned), "skipped": dict(sorted(skipped.items()))}
    errors = cur_doc.get("errors") if isinstance(cur_doc.get("errors"), list) else []
    current = {(item["check_id"], item["path"], item["line"]) for item in _findings(cur_doc, repo)}

    # Rule 2: path mapping.
    renames: dict[str, str] = {}
    deleted: set[str] = set()
    for line in _git(repo, "diff", "-M", "--name-status", base_sha, "HEAD").stdout.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("R") and len(parts) == 3:
            renames[parts[1]] = parts[2]
        elif parts[0] == "D" and len(parts) == 2:
            deleted.add(parts[1])
    report["git"]["renames"] = renames
    report["git"]["deleted"] = sorted(deleted)

    for item in base_findings:
        path = item["path"]
        mapped_path = renames.get(path, path)
        disk = repo / mapped_path
        on_disk = disk.is_file()
        base_text = _git(repo, "show", f"{base_sha}:{path}").stdout
        match_lines = base_text.splitlines()[item["line"] - 1:item["end_line"]]
        entry = {**item, "mapped_path": mapped_path,
                 "match_sha256": hashlib.sha256("\n".join(match_lines).encode()).hexdigest(),
                 "fix_claim": False}
        causes: list[str] = []
        changed_at_match = False
        mapped_line = None
        if on_disk:
            # Rule 3: line mapping against the bytes currently on disk.
            hunks = _hunks(base_text, disk.read_text(encoding="utf-8", errors="replace"))
            mapped = [_map_line(number, hunks) for number in range(item["line"], item["end_line"] + 1)]
            changed_at_match = any(value is None for value in mapped)
            mapped_line = mapped[0]
        entry["mapped_line"] = mapped_line
        entry["on_disk"] = on_disk
        entry["removed_from_git_index"] = path in deleted
        # Rule 4: still present.
        if on_disk and not changed_at_match and (item["check_id"], mapped_path, mapped_line) in current:
            entry.update(presence="STILL_PRESENT", causes=[])
            report["findings"].append(entry)
            continue
        # Rule 5: collect every applicable cause.
        if changed_at_match:
            causes.append("CODE_CHANGED_AT_MATCH")
        if not on_disk:
            causes.append("FILE_DELETED")
        if on_disk and (mapped_path in skipped or mapped_path not in scanned):
            causes.append("SCOPE_EXCLUDED")
            entry["scope_reason"] = skipped.get(mapped_path, "not_in_scanned_list")
        base_block = _rule_block(base_rule_text, item["check_id"])
        cur_block = _rule_block(cur_rule_text, item["check_id"])
        if cur_block is None:
            causes.append("RULE_DISABLED")
        elif base_block != cur_block:
            causes.append("RULE_CHANGED")
        for error in errors:
            text = json.dumps(error)
            if mapped_path in text:
                causes.append("SCAN_INCOMPLETE")
                break
        # Rules 6-7: unexplained when empty; never a fix claim.
        entry.update(presence="DISAPPEARED", causes=causes)
        if causes == ["CODE_CHANGED_AT_MATCH"]:
            entry["note"] = "manual_review_required_not_evidence_of_fix"
        report["findings"].append(entry)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("--repo", "--base-sha", "--base-json", "--cur-json", "--base-rules", "--cur-rules"):
        parser.add_argument(name, required=True)
    parser.add_argument("--base-exit", type=int, required=True)
    parser.add_argument("--cur-exit", type=int, required=True)
    args = parser.parse_args()
    report = compare(Path(args.repo), args.base_sha, Path(args.base_json), Path(args.cur_json),
                     args.base_exit, args.cur_exit, Path(args.base_rules), Path(args.cur_rules))
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
