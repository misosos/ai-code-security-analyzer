"""Command-line entry point. Analysis commands will be added in later phases."""

import argparse
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai_code_security_analyzer",
        description="AI Code Security Analyzer",
    )
    parser.parse_args(argv)
    return 0
