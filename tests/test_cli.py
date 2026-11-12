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
    assert "SAST Review Workspace" in result.stdout
    assert "--help" in result.stdout
