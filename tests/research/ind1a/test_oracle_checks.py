"""감사 assertion. 확인된 실패를 유지하며 일반 pytest 수집에도 포함한다."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from audit_ind1a import compare_case, load_oracle


@pytest.mark.parametrize("case", load_oracle(), ids=lambda case: case["id"])
def test_실행전_고정한_구조_계약(case):
    report = compare_case(case)
    assert report["result"] == "MATCH", {"id": case["id"], "differences": report["differences"],
                                        "expected": report["expected"],
                                        "actual": report["execution"]["payload"]}
