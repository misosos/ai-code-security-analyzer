"""탐지 정확도와 구별되는, 연구용 부모/자식 실패 경계 검증."""
from dataclasses import asdict
import json
from pathlib import Path
import signal
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_ind1a import load_oracle
from ind1a_isolation import run_worker, valid_analysis


def test_실행전_oracle_무결성과_새로운_사례_및_취약점_미확정():
    cases = load_oracle()
    assert len(cases) == 36 and len({item["id"] for item in cases}) == 36
    assert all(item["vulnerability_verified"] is False for item in cases)
    old = Path(__file__).parent / "fixtures/independent_engine_phase1"
    old_inputs = {path.read_text().strip() for path in old.glob("*.js")}
    assert not old_inputs & {case["source"].strip() for case in cases}


def test_자식의_실제_분석과_반환_근거_범위_검증():
    source = b"function action(data){const dispatch=eval;dispatch(data);}"
    result = run_worker(source)
    assert result.outcome == "RETURNED" and result.reaped
    data = result.payload["analysis"]
    assert data["kinds"] == ["SIMPLE_ALIAS_CALL"] and data["verification"] == ["UNVERIFIED"]
    start, end = data["calls"][0]
    assert source[start:end] == b"dispatch(data)"
    _, _, start, end = data["bindings"][0]
    assert source[start:end] == b"eval"
    assert not valid_analysis({**data, "raw_source": "forbidden"}, len(source))
    assert not valid_analysis({**data, "calls": [[0, 10000]]}, len(source))


@pytest.mark.parametrize("mode,outcome", [("native_wait", "WALL_TIMEOUT"), ("output", "OUTPUT_LIMIT"),
                                         ("signal", "SIGNALLED"), ("nonzero", "NONZERO_EXIT"), ("invalid", "INVALID_OUTPUT")])
def test_네이티브_대기_신호_출력_오류를_정상_분석으로_승격하지_않는다(mode, outcome):
    result = run_worker(mode=mode, wall_seconds=0.75 if mode == "native_wait" else 3, output_limit=1024)
    assert result.outcome == outcome and result.reaped and result.payload is None
    if mode == "signal":
        assert result.signal_number == signal.SIGTERM
    assert "SYNTHETIC_OUTPUT_CANARY" not in json.dumps(asdict(result))
    assert run_worker(b"eval(input);").outcome == "RETURNED"


def test_부모_환경을_제거하지만_파일_네트워크_sandbox는_아니다(monkeypatch):
    monkeypatch.setenv("IND1A_ENV_CANARY", "SYNTHETIC_PRIVATE_VALUE")
    result = run_worker(mode="capabilities")
    assert result.outcome == "RETURNED" and result.reaped
    assert result.payload["parent_canary_inherited"] is False
    assert result.payload["file_read_possible"] is True
    assert result.payload["loopback_bind_possible"] is True


def test_위험한_과거_callback은_명시적_opt_in_없이_실행할_수_없다():
    with pytest.raises(ValueError, match="requires_opt_in"):
        run_worker(mode="historical_callback")
    with pytest.raises(ValueError, match="input_invalid"):
        run_worker(b"x" * 131073)
    with pytest.raises(ValueError, match="wall_invalid"):
        run_worker(wall_seconds=float("inf"))
