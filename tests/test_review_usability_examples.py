from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANARY = "SYNTHETIC_REVIEW_DISPLAY_CANARY"


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
