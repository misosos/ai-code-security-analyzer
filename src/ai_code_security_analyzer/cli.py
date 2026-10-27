"""Command-line input, scan orchestration, and exit codes."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from ai_code_security_analyzer.reporter import (
    build_json_report,
    render_json,
    render_text,
    validate_output_path,
    write_new_report,
)
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter


EXIT_COMPLETE = 0
EXIT_PARTIAL = 1
EXIT_INVALID_INPUT = 2
EXIT_FAILED = 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai_code_security_analyzer",
        description="AI Code Security Analyzer",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a local directory with trusted local Semgrep rules")
    scan.add_argument("--path", required=True, type=Path, metavar="TARGET", help="local target directory")
    scan.add_argument("--rules", required=True, type=Path, metavar="RULE_FILE", help="trusted local YAML rules file")
    scan.add_argument("--format", choices=("text", "json"), default="text", help="report format (default: text)")
    scan.add_argument("--output", type=Path, metavar="FILE", help="create a new JSON report file")
    return parser


def _exit_code(status: ScanStatus) -> int:
    if status is ScanStatus.COMPLETED:
        return EXIT_COMPLETE
    if status is ScanStatus.PARTIAL:
        return EXIT_PARTIAL
    return EXIT_FAILED


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "scan":
        return EXIT_INVALID_INPUT

    if args.output is not None and args.format != "json":
        print("error: --output requires --format json", file=sys.stderr)
        return EXIT_INVALID_INPUT
    try:
        target = args.path.resolve()
        rules = args.rules.resolve()
        if not target.is_dir():
            raise ValueError("target must be a local directory")
        if not rules.is_file() or rules.suffix.lower() not in {".yml", ".yaml"}:
            raise ValueError("rules must be a local YAML file")
        if args.output is not None:
            validate_output_path(args.output, target, rules.parent)
        adapter = SemgrepAdapter(rules.parent)
    except (OSError, ValueError):
        print("error: invalid local target, rules, or output path", file=sys.stderr)
        return EXIT_INVALID_INPUT
    try:
        scanned = adapter.scan(target, rules)
    except ValueError:
        print("error: invalid local target or rules", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except OSError:
        print("error: scan could not be started", file=sys.stderr)
        return EXIT_FAILED

    if args.format == "json":
        report = render_json(build_json_report(scanned, target, rules))
        if args.output is not None:
            try:
                write_new_report(args.output, report, target, rules.parent)
            except (OSError, ValueError):
                print("error: could not create JSON report", file=sys.stderr)
                return EXIT_FAILED
        else:
            print(report)
    else:
        print(render_text(scanned, target, rules))
    return _exit_code(scanned.status)
