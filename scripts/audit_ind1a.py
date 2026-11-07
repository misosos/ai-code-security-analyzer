"""IND-1A 감사. Oracle 불일치 시 exit 1이며 탐지 엔진을 수정하지 않는다."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from ind1a_isolation import run_worker

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "tests/fixtures/independent_engine_phase1a/oracle.json"
ORACLE_SHA256 = "974d08fc3f8bd451405c365d49f919d0142886f289f4125f699179eba8344614"


def load_oracle():
    raw = ORACLE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORACLE_SHA256:
        raise ValueError("ind1a_oracle_changed")
    return json.loads(raw)["cases"]


def compare_case(case):
    execution = run_worker(case["source"].encode())
    actual = execution.payload["analysis"] if execution.payload else None
    expected = case["expected"]
    differences = []
    if execution.outcome != "RETURNED":
        differences.append("WORKER_NOT_RETURNED")
    else:
        if actual["status"] != expected["status"]:
            differences.append("STATUS")
        if actual["kinds"] != expected["kinds"]:
            differences.append("OBSERVATIONS")
        if not set(expected["required_diagnostics"]) <= set(actual["diagnostics"]):
            differences.append("DIAGNOSTICS")
    return {"id": case["id"], "result": "MISMATCH" if differences else "MATCH", "differences": differences,
            "expected": expected, "execution": asdict(execution)}


def main():
    parser = argparse.ArgumentParser(description="합성 입력과 별도 프로세스만 사용하는 IND-1A 감사")
    parser.add_argument("--suite", choices=("oracle", "isolation", "syntax"), default="oracle")
    parser.add_argument("--native-repro", action="store_true")
    options = parser.parse_args()
    if options.native_repro and options.suite != "isolation":
        raise ValueError("ind1a_native_requires_isolation_suite")
    if options.suite == "syntax":
        node = shutil.which("node")
        if node is None or not subprocess.run([node, "--version"], capture_output=True, text=True, check=True,
                                              env={"LANG": "C"}, timeout=2).stdout.startswith("v24."):
            raise ValueError("ind1a_node24_required")
        rows = []
        with tempfile.TemporaryDirectory(prefix="aicsa-ind1a-syntax-") as temporary:
            for case in load_oracle():
                mode = "module" if case["javascript_validity"] == "VALID_MODULE" else "commonjs"
                # 고정된 작은 합성 입력의 parse-only 검증이다. JavaScript를 실행하지 않는다.
                result = subprocess.run([node, "--check", "--input-type=" + mode], input=case["source"].encode(),
                                        cwd=temporary, env={"LANG": "C"}, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=2, check=False)
                valid = not case["javascript_validity"].startswith("INVALID")
                rows.append({"id": case["id"], "returncode": result.returncode, "oracle_agrees": (result.returncode == 0) == valid})
        print(json.dumps({"version": "ind1a-audit/v1", "suite": "syntax", "results": rows}, indent=2))
        return 0 if all(row["oracle_agrees"] for row in rows) else 1
    if options.suite == "oracle":
        rows = [compare_case(case) for case in load_oracle()]
        mismatches = sum(row["result"] == "MISMATCH" for row in rows)
        print(json.dumps({"version": "ind1a-audit/v1", "suite": "oracle", "cases": len(rows),
                          "matches": len(rows) - mismatches, "mismatches": mismatches, "results": rows}, indent=2))
        return 1 if mismatches else 0
    modes = ["analyze", "native_wait", "cpu", "memory", "output", "signal", "nonzero", "invalid", "capabilities"]
    if options.native_repro:
        modes.append("historical_callback")
    results = {mode: asdict(run_worker(b"eval(input);" if mode == "analyze" else b"", mode=mode,
                                      wall_seconds=4.5 if mode == "cpu" else 1.0 if mode == "native_wait" else 3.0,
                                      allow_native_repro=options.native_repro)) for mode in modes}
    print(json.dumps({"version": "ind1a-audit/v1", "suite": "isolation", "results": results}, indent=2))
    # 정상 실행 완료 코드이지 CPU/메모리/권한 격리 GO를 뜻하지 않는다.
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("ind1a_audit_failed", file=sys.stderr)
        raise SystemExit(2)
