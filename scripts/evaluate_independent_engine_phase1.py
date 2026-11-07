"""합성 개발 입력의 IND-1 결과와 선택적인 실제 Semgrep baseline 측정."""
from dataclasses import asdict
import json
import re
from pathlib import Path
import sys
import tempfile
from time import perf_counter

from ai_code_security_analyzer.research.independent_eval import analyze_javascript

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "independent_engine_phase1"


def main():
    if sys.argv[1:] not in ([], ["--semgrep"]):
        raise ValueError("ind1_arguments_invalid")
    cases = json.loads((FIXTURES / "manifest.json").read_text())
    inputs = {case["file"]: (FIXTURES / case["file"]).read_bytes() for case in cases}
    results = []
    started = perf_counter()
    for case in cases:
        name = case["file"]
        result = analyze_javascript(inputs[name], name)
        if result.status != case["expected_status"] or [item.kind for item in result.observations] != case["expected_kinds"]:
            raise ValueError("ind1_expected_structure_mismatch")
        results.append({"file": name, "provenance": case["provenance"], "independent": asdict(result)})
    independent_ms = (perf_counter() - started) * 1000
    semgrep = {"status": "NOT_RUN"}
    if sys.argv[1:]:
        # 연구 비교만 기존 Adapter를 명시적으로 호출한다. 독립 엔진에서는 import하지 않는다.
        from ai_code_security_analyzer.semgrep_adapter import SemgrepAdapter, ScanStatus
        with tempfile.TemporaryDirectory(prefix="ai-csa-ind1-comparison-") as temporary:
            valid, malformed = Path(temporary) / "valid", Path(temporary) / "malformed"
            valid.mkdir(mode=0o700); malformed.mkdir(mode=0o700)
            for case in cases:
                directory = malformed if case["expected_status"] == "PARSE_ERROR" else valid
                (directory / case["file"]).write_bytes(inputs[case["file"]])
            adapter = SemgrepAdapter(ROOT / "rules")
            measurements = []
            for label, target in (("valid_syntax", valid), ("malformed_syntax", malformed)):
                start = perf_counter()
                result = adapter.scan(target, ROOT / "rules" / "security-baseline.yml")
                elapsed_ms = (perf_counter() - start) * 1000
                if result.status not in {ScanStatus.COMPLETED, ScanStatus.PARTIAL} or result.semgrep_version != "1.182.1":
                    raise ValueError("ind1_semgrep_" + result.status.value)
                measurements.append({"batch": label, "scan_status": result.status.value, "issues": list(result.issues),
                                     "elapsed_ms": round(elapsed_ms, 3), "finding_count": len(result.findings)})
                for row in results:
                    if row["file"] in {path.name for path in target.iterdir()}:
                        matching = [finding for finding in result.findings if finding.file_path == row["file"]]
                        row["semgrep"] = {"batch": label, "batch_status": result.status.value,
                                          "matches": [{"rule_id": finding.rule_id, "line": finding.line_number} for finding in matching]}
                if any(path.read_bytes() != inputs[path.name] for path in target.iterdir()):
                    raise ValueError("ind1_input_changed")
            semgrep = {"version": "1.182.1", "batches": measurements}
    if any((FIXTURES / name).read_bytes() != data for name, data in inputs.items()):
        raise ValueError("ind1_fixture_changed")
    print(json.dumps({"contract_version": "ind1-comparison-research/v1", "repetitions": 1,
                      "independent_total_ms": round(independent_ms, 3), "semgrep": semgrep, "cases": results,
                      "interpretation": "SYNTHETIC_STRUCTURE_COMPARISON_NOT_VULNERABILITY_ACCURACY"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"ind1_[a-z_]+", str(error)) else "ind1_experiment_failed"
        print(code, file=sys.stderr)
        raise SystemExit(1)
