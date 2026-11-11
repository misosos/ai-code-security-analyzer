"""Arm C: minimal scan-integrity check over Semgrep verbose JSON (stdlib only).

Implements PROTOCOL.md section 5 "Arm C" rules 1-6. A PASS means only that no
incompleteness signal was found against the declared intent; it is not a
statement that the code is safe.

Usage:
  integrity_check.py --json F --exit N --target DIR --root DIR --rules F \
      [--expected-rules-sha256 HEX]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

SOURCE_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx")
SOURCE_NAMES = ("firestore.rules",)
DECLARED_EXCLUSIONS = ("node_modules/", ".git/")


def _rel(path: str, root: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root).as_posix()
        except ValueError:
            return path
    return candidate.as_posix()


def _excluded(relative: str, exclusions: tuple[str, ...]) -> bool:
    return any(relative == item.rstrip("/") or relative.startswith(item) for item in exclusions)


def _is_source(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return name.endswith(SOURCE_EXTENSIONS) or name in SOURCE_NAMES


def _classify_error(error: object) -> str:
    # PROTOCOL.md rule 2, in its stated order, over the error type and message.
    if isinstance(error, dict):
        text = (json.dumps(error.get("type")) + " " + json.dumps(error.get("message"))).lower()
    else:
        text = json.dumps(error).lower()
    if "timeout" in text:
        return "TIMEOUT"
    if any(token in text for token in ("pars", "syntax", "lex")):
        return "PARSE"
    if any(token in text for token in ("rule", "pattern", "config", "yaml")):
        return "RULE"
    return "GENERIC"


def check(json_text: str, exit_code: int, target: Path, root: Path, rules_file: Path,
          expected_rules_sha256: str | None, exclusions: tuple[str, ...] = DECLARED_EXCLUSIONS) -> dict:
    root = root.resolve()
    reasons: list[dict] = []
    try:
        document = json.loads(json_text)
        if not isinstance(document, dict) or not isinstance(document.get("results"), list):
            document = None
    except ValueError:
        document = None
    rules_sha = hashlib.sha256(rules_file.read_bytes()).hexdigest() if rules_file.is_file() else None
    report: dict = {
        "tool": "d2-integrity-check/v1",
        "exit_code": exit_code,
        "semgrep_version": (document or {}).get("version"),
        "target": {"relative_to_root": _rel(str(target), root), "exists": target.exists()},
        "rules_sha256": rules_sha,
        "expected_rules_sha256": expected_rules_sha256,
    }

    # Rule 1
    if exit_code != 0:
        reasons.append({"class": "SCAN_FAILED", "detail": f"exit_code={exit_code}"})
    if document is None:
        reasons.append({"class": "SCAN_FAILED", "detail": "json_invalid"})
    else:
        # Rule 2
        errors = document.get("errors") if isinstance(document.get("errors"), list) else []
        report["errors"] = [{"type": error.get("type") if isinstance(error, dict) else None,
                             "path": _rel(error["path"], root) if isinstance(error, dict) and isinstance(error.get("path"), str) else None,
                             "level": error.get("level") if isinstance(error, dict) else None}
                            for error in errors]
        for error in errors:
            reasons.append({"class": _classify_error(error),
                            "detail": json.dumps(error.get("type") if isinstance(error, dict) else None)[:120]})
        paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
        scanned = sorted({_rel(item, root) for item in paths.get("scanned", []) if isinstance(item, str)})
        skipped = [{"path": _rel(item["path"], root), "reason": item.get("reason")}
                   for item in paths.get("skipped", []) if isinstance(item, dict) and isinstance(item.get("path"), str)]
        report["scanned"], report["skipped"] = scanned, skipped
        # Rule 3
        for item in skipped:
            relative = item["path"]
            if _excluded(relative, exclusions):
                continue
            if (root / relative).is_dir() or _is_source(relative):
                reasons.append({"class": "SCOPE", "detail": f"skipped:{relative}:{item['reason']}"})
        # Rule 4
        expected_sources: list[str] = []
        for directory, names, files in os.walk(root):
            relative_dir = Path(directory).relative_to(root).as_posix()
            names[:] = sorted(name for name in names
                              if not _excluded((f"{relative_dir}/{name}" if relative_dir != "." else name) + "/", exclusions))
            for name in sorted(files):
                relative = f"{relative_dir}/{name}" if relative_dir != "." else name
                if _is_source(relative) and not _excluded(relative, exclusions):
                    expected_sources.append(relative)
        report["expected_sources"] = expected_sources
        scanned_set = set(scanned)
        for relative in expected_sources:
            if relative not in scanned_set:
                reasons.append({"class": "SCOPE", "detail": f"not_scanned:{relative}"})
        # Rule 5
        if expected_sources and not scanned:
            reasons.append({"class": "SCOPE", "detail": "no_files_scanned"})
        # Rule 6b
        if document.get("skipped_rules"):
            reasons.append({"class": "RULE", "detail": "skipped_rules"})
    # Rule 6a
    if expected_rules_sha256 is not None and rules_sha != expected_rules_sha256:
        reasons.append({"class": "RULE", "detail": "rules_sha256_mismatch"})

    report["reasons"] = reasons
    report["verdict"] = "FLAG" if reasons else "PASS"
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("--json", "--target", "--root", "--rules"):
        parser.add_argument(name, required=True)
    parser.add_argument("--exit", type=int, required=True)
    parser.add_argument("--expected-rules-sha256")
    args = parser.parse_args()
    report = check(Path(args.json).read_text(encoding="utf-8"), args.exit, Path(args.target), Path(args.root),
                   Path(args.rules), args.expected_rules_sha256)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
