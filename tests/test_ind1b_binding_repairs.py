"""IND-1B 합성 회귀: 쓰기 target과 읽기·선언, switch 환경을 구분한다."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from ind1a_isolation import run_worker
from ai_code_security_analyzer.research.independent_eval import analyze_javascript


CASES = [
    ("parenthesized_comment", b"let run=eval; ( /* target */ (run))=other; run(input);", "PARTIAL", [], "BINDING_REASSIGNED"),
    ("augmented", b"let run=eval; (run)+=other; run(input);", "PARTIAL", [], "BINDING_REASSIGNED"),
    ("update", b"let run=eval; (run)++; run(input);", "PARTIAL", [], "BINDING_REASSIGNED"),
    ("for_in", b"let run=eval; for((run) in replacements){} run(input);", "PARTIAL", [], "BINDING_REASSIGNED"),
    ("nested_identifier", b"let run=eval; [{inner:[run]}]=replacements; run(input);", "PARTIAL", [], "BINDING_REASSIGNED"),
    ("rest_identifier", b"let run=eval; [...run]=replacement; run(input);", "PARTIAL", [], "BINDING_REASSIGNED"),
    ("nested_member", b"({outer:[{value:policy.eval}]}=replacement); eval(input);", "PARTIAL", [], "DYNAMIC_BINDING"),
    ("subscript", b"[policy['eval']]=replacement; eval(input);", "PARTIAL", [], "DYNAMIC_BINDING"),
    ("rest_member", b"[...policy.destination]=replacement; eval(input);", "PARTIAL", [], "DYNAMIC_BINDING"),
    ("shorthand_global", b"({eval}=replacement); eval(input);", "PARTIAL", [], "DYNAMIC_BINDING"),
    ("default_member", b"({value:policy.eval=fallback}=replacement); eval(input);", "PARTIAL", [], "DYNAMIC_BINDING"),
    ("computed_key_read", b"let local; ({[policy.eval]:local}=source); eval(input);", "ANALYZED", ["DIRECT_CALL"], None),
    ("default_value_read", b"let local; ({value:local=policy.eval}=source); eval(input);", "ANALYZED", ["DIRECT_CALL"], None),
    ("destructuring_declaration", b"const {value:local}=policy.eval; eval(input);", "ANALYZED", ["DIRECT_CALL"], None),
    ("read_before_alias", b"const local=policy['eval']; const run=eval; run(input);", "ANALYZED", ["SIMPLE_ALIAS_CALL"], None),
    ("key_not_target", b"let local; ({eval:local}=source); eval(input);", "ANALYZED", ["DIRECT_CALL"], None),
    ("different_binding_write", b"const run=eval; let local; (local)=other; run(input);", "ANALYZED", ["SIMPLE_ALIAS_CALL"], None),
    ("local_eval_write", b"function f(eval){(eval)=other;eval(input);} eval(input);", "ANALYZED", ["DIRECT_CALL"], "LOCAL_EVAL_SHADOW"),
    ("switch_const_discriminant", b"switch(eval(input)){case 1:const eval=other;}", "ANALYZED", ["DIRECT_CALL"], None),
    ("switch_const_case_tdz", b"switch(input){case eval(input):const eval=other;}", "ANALYZED", [], "LOCAL_EVAL_SHADOW"),
    ("switch_var_hoisting", b"function f(){switch(eval(input)){case 1:var eval;}}", "ANALYZED", [], "LOCAL_EVAL_SHADOW"),
    ("switch_lexical_not_leaking", b"switch(input){case 1:let eval=other;} eval(input);", "ANALYZED", ["DIRECT_CALL"], None),
    ("switch_default_tdz", b"switch(input){default:eval(input);case 1:let eval=other;}", "ANALYZED", [], "LOCAL_EVAL_SHADOW"),
    ("nested_switch", b"switch(eval(first)){case 1:switch(eval(second)){case 2:let eval=other;}}", "ANALYZED", ["DIRECT_CALL", "DIRECT_CALL"], None),
    ("before_switch", b"const result=eval(input);switch(result){case 1:let eval=other;}", "ANALYZED", ["DIRECT_CALL"], None),
    ("switch_nested_block", b"switch(eval(input)){case 1:{let eval=other;eval(input);}}", "ANALYZED", ["DIRECT_CALL"], "LOCAL_EVAL_SHADOW"),
    ("switch_outer_parameter", b"function f(eval){switch(eval(input)){case 1:let eval=other;}}", "ANALYZED", [], "LOCAL_EVAL_SHADOW"),
    ("switch_alias_still_unsupported", b"switch(input){case 1:const run=eval;run(input);}", "PARTIAL", [], "ALIAS_ORDER_OR_CONTROL_FLOW"),
]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case[0])
def test_쓰기와_scope_회귀(case):
    _, source, status, kinds, diagnostic = case
    execution = run_worker(source)
    assert execution.outcome == "RETURNED" and execution.reaped
    result = execution.payload["analysis"]
    assert result["status"] == status
    assert result["kinds"] == kinds
    if diagnostic:
        assert diagnostic in result["diagnostics"]
    elif status == "ANALYZED":
        assert not result["diagnostics"]
    assert all(value == "UNVERIFIED" for value in result["verification"])


def test_미지원_쓰기_target을_정상_별칭으로_승격하지_않는다():
    # ECMAScript 유효성 밖의 LHS다. 문법 복구 또는 미지원 진단 어느 쪽도 안전 판정은 아니다.
    execution = run_worker(b"const run=eval;(run, other)=replacement;run(input);")
    assert execution.outcome == "RETURNED"
    result = execution.payload["analysis"]
    assert result["status"] in {"PARSE_ERROR", "PARTIAL"}
    assert not result["kinds"]
    assert set(result["diagnostics"]) & {"PARSE_ERROR", "UNSUPPORTED_CONSTRUCT"}


def test_switch_수정이_원본_위치나_결과_계약을_변경하지_않는다():
    source = 'const 메시지="값";\nswitch (eval(input)) {case 1:let eval;}'.encode()
    result = analyze_javascript(source, "fixture.js")
    assert result.status == "ANALYZED"
    observation, = result.observations
    assert source[observation.call.start_byte:observation.call.end_byte] == b"eval(input)"
    assert observation.callee.start_line == 2 and observation.callee.start_byte_column == 9
    assert observation.verification_status == "UNVERIFIED"
    assert result.contract_version == "independent-eval-research/v1"
    assert "VULNERABILITY_UNVERIFIED" in result.limitations
