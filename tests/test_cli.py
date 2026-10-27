import subprocess
import sys


def test_module_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ai_code_security_analyzer", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "AI Code Security Analyzer" in result.stdout
    assert "--help" in result.stdout
