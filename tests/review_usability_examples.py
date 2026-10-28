"""Render reproducible synthetic screens for a future analyst study."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus
from ai_code_security_analyzer.semgrep_parser import _parse_semgrep_json_internal
from ai_code_security_analyzer.taint_evidence import build_taint_evidence


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TAINT_RULE = RULES / "experimental" / "javascript-eval-taint.yml"
PATTERN_RULE = RULES / "security-baseline.yml"
CANARY = "SYNTHETIC_REVIEW_DISPLAY_CANARY"
CASES = ("taint", "pattern", "partial", "failed", "zero")


def render_case(name: str) -> str:
    """Return one complete review screen produced from fixed synthetic metadata."""
    if name not in CASES:
        raise ValueError("unsupported synthetic review case")
    if name == "zero":
        return render_review(ScanResult(ScanStatus.COMPLETED, (), (), 0, "1.182.1"), ())

    rule_id = (
        "experimental.javascript-eval-taint"
        if name in {"taint", "partial", "failed"}
        else "baseline.javascript-dynamic-eval"
    )
    rule_file = TAINT_RULE if rule_id.startswith("experimental.") else PATTERN_RULE
    with TemporaryDirectory(prefix="synthetic-review-display-") as temporary:
        target = Path(temporary)
        raw = {
            "version": "1.182.1",
            "engine_requested": "OSS",
            "results": [
                {
                    "check_id": rule_id,
                    "path": "src/synthetic-review.ts",
                    "start": {"line": 12, "col": 3},
                    "end": {"line": 12, "col": 9},
                    "extra": {
                        "message": f"Synthetic tool message {CANARY}",
                        "severity": "ERROR",
                        "engine_kind": "OSS",
                        "lines": f"eval('{CANARY}')",
                    },
                }
            ],
            "errors": [],
        }
        parsed = _parse_semgrep_json_internal(json.dumps(raw).encode("utf-8"), target)
        finding = parsed.parsed.findings[0]
        status = ScanStatus.PARTIAL if name == "partial" else ScanStatus.COMPLETED
        issues = ("semgrep_skipped_paths",) if name == "partial" else ()
        scan = ScanResult(status, (finding,), issues, 0, "1.182.1")
        evidence = (
            build_taint_evidence(
                parsed.document,
                parsed.result_findings,
                target,
                rules_file=rule_file,
                trusted_rules_directory=RULES,
            )
            if rule_file is TAINT_RULE
            else ()
        )
        if name == "failed":
            scan = replace(scan, status=ScanStatus.TIMED_OUT, issues=("semgrep_timeout",), exit_code=None)
        return render_review(
            scan,
            evidence,
            rules_file=rule_file,
            trusted_rules_directory=RULES,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=(*CASES, "all"), default="all")
    args = parser.parse_args()
    names = CASES if args.case == "all" else (args.case,)
    for name in names:
        print(f"===== SYNTHETIC CASE: {name} =====")
        print(render_case(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
