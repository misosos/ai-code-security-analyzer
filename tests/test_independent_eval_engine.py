"""취약점 정답 집합이 아닌, IND-1의 지원 구문과 보수적 거부 계약을 검증한다."""
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from ai_code_security_analyzer.research import independent_eval as engine

FIXTURES = Path(__file__).parent / "fixtures" / "independent_engine_phase1"
CASES = json.loads((FIXTURES / "manifest.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["file"])
def test_고정된_합성_지원범위(case):
    result = engine.analyze_javascript((FIXTURES / case["file"]).read_bytes(), case["file"])
    assert result.status.value == case["expected_status"]
    assert [observation.kind for observation in result.observations] == case["expected_kinds"]
    assert all(observation.verification_status == "UNVERIFIED" for observation in result.observations)
    assert "VULNERABILITY_UNVERIFIED" in result.limitations


def test_별칭_선언과_초기_eval_참조와_호출의_정확한_바이트_범위():
    source = b'function sample(input) { const run = eval; run(input); }'
    result = engine.analyze_javascript(source, "fixture.js")
    assert result.status == engine.AnalysisStatus.ANALYZED
    observation, = result.observations
    assert source[observation.alias_declaration.start_byte:observation.alias_declaration.end_byte] == b"run = eval"
    assert source[observation.eval_reference.start_byte:observation.eval_reference.end_byte] == b"eval"
    assert source[observation.callee.start_byte:observation.callee.end_byte] == b"run"
    assert source[observation.call.start_byte:observation.call.end_byte] == b"run(input)"
    assert observation.alias_declaration.end_byte < observation.call.start_byte
    assert observation.function_scope.start_byte == 0


@pytest.mark.parametrize("source,count", [
    (b'eval(x); let eval = other;', 0),
    (b'function f(input) { eval(input); var eval; }', 0),
    (b'const f = function eval(input) { eval(input); }; eval(x);', 1),
    (b'try {} catch(eval) { eval(x); } eval(x);', 1),
    (b'for(let eval of inputs) eval(x); eval(x);', 1),
    (b'for(var eval of inputs) eval(x); eval(x);', 0),
    (b'const {x: eval} = obj; eval(x);', 0),
    (b'import {eval as other} from "x"; eval(x);', 1),
    (b'import {other as eval} from "x"; eval(x);', 0),
    (b'import eval from "x"; eval(x);', 0),
    (b'function f(eval, input) { const run = eval; run(input); }', 0),
    (b'const f = input => eval(input);', 1),
    (b'function f() { { const run = eval; run(x); } }', 1),
    (b'function f(){const run = eval; {const run=other;run(x);} run(x);}', 1),
])
def test_매개변수_선언_블록_import와_함수_범위의_shadowing(source, count):
    result = engine.analyze_javascript(source)
    assert len(result.observations) == count
    assert result.status not in {engine.AnalysisStatus.PARSE_ERROR, engine.AnalysisStatus.UNAVAILABLE}


@pytest.mark.parametrize("source,code", [
    (b'const run=eval;run(x);run=other;', 'BINDING_REASSIGNED'),
    (b'let run=eval;[run]=other;run(x);', 'BINDING_REASSIGNED'),
    (b'let run=eval;run++;run(x);', 'BINDING_REASSIGNED'),
    (b'function f(){run(x);const run=eval;}', 'ALIAS_ORDER_OR_CONTROL_FLOW'),
    (b'const run=eval;if(flag) run(x);', 'ALIAS_ORDER_OR_CONTROL_FLOW'),
    (b'var run=eval;var run=other;run(x);', 'AMBIGUOUS_BINDING'),
    (b'with(obj){eval(x);}', 'DYNAMIC_BINDING'),
    (b'eval=other;eval(x);', 'DYNAMIC_BINDING'),
    (b'delete globalThis.eval;eval(x);', 'DYNAMIC_BINDING'),
    (b'globalThis.eval=other;eval(x);', 'DYNAMIC_BINDING'),
    (b'function f(){if(x){function eval(){}}eval(x);}', 'ANNEX_B_BINDING'),
    (b'class C { method(){eval(x);} }', 'UNSUPPORTED_CONSTRUCT'),
    (b'const f = (x=eval(y))=>x;', 'UNSUPPORTED_CONSTRUCT'),
    (b'eval.call(null,x);', 'UNSUPPORTED_CALLEE'),
    (b'eval`input`;', 'UNSUPPORTED_CALLEE'),
    (b'const run=eval;run`input`;', 'UNSUPPORTED_CALLEE'),
])
def test_모호한_참조와_미지원은_안전으로_변환하지_않는다(source, code):
    result = engine.analyze_javascript(source)
    assert result.status == engine.AnalysisStatus.PARTIAL
    assert not result.observations
    assert code in [diagnostic.code.value for diagnostic in result.diagnostics]


def test_원문_식별자_비밀정보와_절대경로를_결과에_보관하지_않는다():
    source = b'const secretAliasName = eval; secretAliasName("PRIVATE_SOURCE_CANARY");'
    result = engine.analyze_javascript(source, "fixture.js")
    serialized = json.dumps(asdict(result))
    assert result.observations
    assert "secretAliasName" not in serialized and "PRIVATE_SOURCE_CANARY" not in serialized
    for label in ("/private/project.js", "../project.js", "C:\\project.js", "a/../project.js", "a//x.js"):
        rejected = engine.analyze_javascript(source, label)
        assert rejected.status == engine.AnalysisStatus.INVALID_INPUT and rejected.file_label is None
        assert label not in json.dumps(asdict(rejected))


def test_semgrep이나_외부명령_네트워크_파일읽기가_필요하지_않다(monkeypatch):
    monkeypatch.setenv("PATH", "")
    with patch.object(subprocess, "Popen", side_effect=AssertionError("external_process_forbidden")), \
         patch("builtins.open", side_effect=AssertionError("file_read_forbidden")), \
         patch("socket.socket", side_effect=AssertionError("network_forbidden")):
        result = engine.analyze_javascript(b'const run=eval;run(x);')
    assert result.status == engine.AnalysisStatus.ANALYZED
    assert [item.kind for item in result.observations] == ["SIMPLE_ALIAS_CALL"]


@pytest.mark.parametrize("source,limits", [
    (b'eval(x);', engine.AnalysisLimits(max_bytes=7)),
    (b'eval(x);', engine.AnalysisLimits(max_nodes=1)),
    (b'(' * 8 + b'eval(x)' + b')' * 8 + b';', engine.AnalysisLimits(max_depth=4)),
    (b'eval(x);eval(y);', engine.AnalysisLimits(max_observations=1)),
    (b'unknown(x);other(y);', engine.AnalysisLimits(max_diagnostics=1)),
])
def test_자원_상한_초과시_관찰을_부분_성공으로_반환하지_않는다(source, limits):
    result = engine.analyze_javascript(source, limits=limits)
    assert result.status == engine.AnalysisStatus.RESOURCE_LIMIT
    assert result.observations == ()


def test_크기경계_깊은중첩과_협력적_시간_제한():
    assert engine.analyze_javascript(b'eval(x);', limits=engine.AnalysisLimits(max_bytes=8)).observations
    nested = b'(' * 1500 + b'eval(x)' + b')' * 1500 + b';'
    assert engine.analyze_javascript(nested).status == engine.AnalysisStatus.RESOURCE_LIMIT
    calls = [0]
    def clock():
        calls[0] += 1
        return 0.0 if calls[0] == 1 else 1.0
    result = engine.analyze_javascript(b'eval(x);', _clock=clock)
    assert result.status == engine.AnalysisStatus.RESOURCE_LIMIT and not result.observations


def test_네이티브_충돌을_재현한_progress_callback_경로는_사용하지_않는다(monkeypatch):
    original = engine.Parser
    class CheckedParser:
        def __init__(self, language): self.parser = original(language)
        def parse(self, source, **options):
            assert callable(source) and "progress_callback" not in options
            return self.parser.parse(source, **options)
    monkeypatch.setattr(engine, "Parser", CheckedParser)
    assert engine.analyze_javascript(b'function f(x){{let eval=other;eval(x);}eval(x);}').observations


def test_파싱오류_잘못된인코딩_내부오류를_구별하고_메시지를_노출하지_않는다(monkeypatch):
    assert engine.analyze_javascript(b'function {').status == engine.AnalysisStatus.PARSE_ERROR
    for source in (b'\xff', b'\x00', "eval(x)"):
        assert engine.analyze_javascript(source).status == engine.AnalysisStatus.INVALID_INPUT
    def unavailable(*_args): raise RuntimeError("PRIVATE_PARSER_CANARY")
    monkeypatch.setattr(engine, "Parser", unavailable)
    result = engine.analyze_javascript(b'eval(x);')
    assert result.status == engine.AnalysisStatus.UNAVAILABLE
    assert "PRIVATE_PARSER_CANARY" not in json.dumps(asdict(result))


def test_동일입력_결정성과_utf8_바이트_열():
    source = 'const 한글 = "값";\neval(한글);'.encode()
    first = engine.analyze_javascript(source)
    assert first == engine.analyze_javascript(source)
    assert first.observations[0].callee.start_line == 2
    assert first.observations[0].callee.start_byte_column == 1


@pytest.mark.parametrize("limits", [{"max_depth": 129}, {"max_nodes": True}, {"max_seconds": float('inf')}, {"max_seconds": 0}])
def test_연구_설정으로_고정_상한을_늘릴_수_없다(limits):
    with pytest.raises(ValueError): engine.AnalysisLimits(**limits)
