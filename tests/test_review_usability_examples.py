from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANARY = "SYNTHETIC_REVIEW_DISPLAY_CANARY"
SPEC = importlib.util.spec_from_file_location(
    "review_usability_examples", ROOT / "tests" / "review_usability_examples.py"
)
assert SPEC is not None and SPEC.loader is not None
EXAMPLES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXAMPLES)


def test_synthetic_review_examples_are_reproducible_and_source_free() -> None:
    env = os.environ.copy()
    env.pop("AI_CODE_SECURITY_RUN_OLLAMA", None)
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "review_usability_examples.py"), "--case", "all"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert CANARY not in result.stdout
    assert "===== SYNTHETIC CASE: taint =====" in result.stdout
    assert "===== SYNTHETIC CASE: pattern =====" in result.stdout
    assert "===== SYNTHETIC CASE: partial =====" in result.stdout
    assert "===== SYNTHETIC CASE: failed =====" in result.stdout
    assert "===== SYNTHETIC CASE: zero =====" in result.stdout
    assert "전체 데이터 흐름 경로 제공 [현재 자료에서 확인 불가]" in result.stdout
    assert "검사 상태: 부분 검사" in result.stdout
    assert "검사 상태: 시간 초과" in result.stdout
    assert "Semgrep 심각도 분류: high (실제 악용 가능성 판정은 아님)" in result.stdout


def test_synthetic_density_metrics_are_deterministic_and_match_rendered_output() -> None:
    for case in ("taint", "pattern", "partial", "failed", "zero"):
        first = EXAMPLES.measure_case(case)
        second = EXAMPLES.measure_case(case)
        rendered = EXAMPLES.render_case(case)
        assert first == second
        assert first["line_count"] == len(rendered.splitlines())
        assert first["utf8_bytes"] == len(rendered.encode("utf-8"))
        assert first["finding_count"] == first["displayed_finding_count"]
        assert first["omission_occurred"] is False
        assert first["omitted_finding_count"] == 0
        assert first["first_scan_status_line"] is not None
        assert CANARY not in str(first)


def test_pattern_density_counts_only_displayed_items_and_reveals_taint_specific_restrictions() -> None:
    metrics = EXAMPLES.measure_case("pattern")
    assert metrics["displayed_supported_claim_count"] == 1
    assert metrics["displayed_restricted_claim_count"] == 10
    assert metrics["analyst_review_item_count"] == 3
    assert metrics["finding_card_line_counts"] == [26]
    assert metrics["omission_occurred"] is False


def test_density_cli_emits_metadata_only_json() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tests" / "review_usability_examples.py"),
            "--case",
            "all",
            "--metrics",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert CANARY not in result.stdout
    assert '"case": "taint"' in result.stdout
    assert '"case": "zero"' in result.stdout
