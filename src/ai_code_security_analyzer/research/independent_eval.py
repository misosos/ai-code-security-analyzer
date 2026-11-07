"""IND-1: 실행·파일 I/O 없이 JavaScript eval 참조 구조만 분석한다."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import math
import re
import time
from typing import Callable, Literal

from tree_sitter import Language, Node, Parser
import tree_sitter_javascript


class AnalysisStatus(StrEnum):
    ANALYZED = "ANALYZED"
    PARTIAL = "PARTIAL"
    PARSE_ERROR = "PARSE_ERROR"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INVALID_INPUT = "INVALID_INPUT"
    UNAVAILABLE = "UNAVAILABLE"


class DiagnosticCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    PARSE_ERROR = "PARSE_ERROR"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    PARSER_UNAVAILABLE = "PARSER_UNAVAILABLE"
    LOCAL_EVAL_SHADOW = "LOCAL_EVAL_SHADOW"
    BINDING_REASSIGNED = "BINDING_REASSIGNED"
    AMBIGUOUS_BINDING = "AMBIGUOUS_BINDING"
    CROSS_FUNCTION_ALIAS = "CROSS_FUNCTION_ALIAS"
    ALIAS_ORDER_OR_CONTROL_FLOW = "ALIAS_ORDER_OR_CONTROL_FLOW"
    UNRESOLVED_CALL = "UNRESOLVED_CALL"
    UNSUPPORTED_CALLEE = "UNSUPPORTED_CALLEE"
    UNSUPPORTED_CONSTRUCT = "UNSUPPORTED_CONSTRUCT"
    ESCAPED_IDENTIFIER = "ESCAPED_IDENTIFIER"
    DYNAMIC_BINDING = "DYNAMIC_BINDING"
    ANNEX_B_BINDING = "ANNEX_B_BINDING"


@dataclass(frozen=True)
class Span:
    start_byte: int
    end_byte: int
    start_line: int
    start_byte_column: int
    end_line: int
    end_byte_column: int


def _span(node: Node) -> Span:
    return Span(node.start_byte, node.end_byte, node.start_point.row + 1,
                node.start_point.column + 1, node.end_point.row + 1, node.end_point.column + 1)


@dataclass(frozen=True)
class EvalObservation:
    kind: Literal["DIRECT_CALL", "SIMPLE_ALIAS_CALL"]
    call: Span
    callee: Span
    function_scope: Span
    alias_declaration: Span | None = None
    eval_reference: Span | None = None
    verification_status: Literal["UNVERIFIED"] = "UNVERIFIED"


@dataclass(frozen=True)
class Diagnostic:
    code: DiagnosticCode
    location: Span | None = None


LIMITATIONS = (
    "SYNTAX_AND_STATIC_BINDING_ONLY", "RUNTIME_GLOBAL_EVAL_IDENTITY_UNVERIFIED",
    "NO_CFG_SSA_OR_TAINT", "NO_CROSS_FILE_ANALYSIS", "EXECUTION_REACHABILITY_UNVERIFIED",
    "UNSUPPORTED_IS_NOT_SAFE", "VULNERABILITY_UNVERIFIED", "COOPERATIVE_TIME_LIMIT_NOT_PROCESS_ISOLATION",
)


@dataclass(frozen=True)
class AnalysisResult:
    status: AnalysisStatus
    file_label: str | None
    observations: tuple[EvalObservation, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    limitations: tuple[str, ...] = LIMITATIONS
    contract_version: Literal["independent-eval-research/v1"] = "independent-eval-research/v1"


@dataclass(frozen=True)
class AnalysisLimits:
    max_bytes: int = 131_072
    max_nodes: int = 20_000
    max_depth: int = 128
    max_observations: int = 64
    max_diagnostics: int = 64
    max_seconds: float = 0.2

    def __post_init__(self):
        for name, ceiling in (("max_bytes", 131_072), ("max_nodes", 20_000), ("max_depth", 128),
                              ("max_observations", 64), ("max_diagnostics", 64)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("invalid_analysis_limits")
        if type(self.max_seconds) not in (int, float) or not math.isfinite(self.max_seconds) or not 0 < self.max_seconds <= 0.2:
            raise ValueError("invalid_analysis_limits")


class _BudgetExceeded(Exception):
    pass


@dataclass
class _Binding:
    declaration: Node
    pattern: Node
    scope: int
    kind: str
    value: Node | None = None
    written: bool = False


@dataclass
class _Scope:
    node: Node
    parent: int | None
    unit: int
    bindings: dict[str, list[_Binding]] = field(default_factory=dict)


_FUNCTIONS = {"function_declaration", "generator_function_declaration", "function_expression",
              "generator_function", "arrow_function", "method_definition"}
_FUNCTION_DECLS = {"function_declaration", "generator_function_declaration"}
# switch 판별식은 바깥 환경에서 평가하고 CaseBlock만 별도 lexical scope를 갖는다.
_SCOPES = {"statement_block", "catch_clause", "for_statement", "for_in_statement", "switch_body", "class_declaration", "class"}


def _pattern_names(node: Node | None):
    """프로퍼티 키와 기본값 표현식을 binding 이름으로 취급하지 않는다."""
    stack = [node] if node else []
    while stack:
        item = stack.pop()
        if item.type in {"identifier", "shorthand_property_identifier_pattern"}:
            yield item
        elif item.type in {"assignment_pattern", "object_assignment_pattern"}:
            left = item.child_by_field_name("left")
            if left: stack.append(left)
        elif item.type == "pair_pattern":
            value = item.child_by_field_name("value")
            if value: stack.append(value)
        elif item.type in {"array_pattern", "object_pattern", "rest_pattern", "formal_parameters"}:
            stack.extend(reversed(item.named_children))


def _write_targets(node: Node):
    """선언과 구분한 쓰기 target. 키·기본값은 순회하지 않고 member/미지원 target도 남긴다."""
    stack = [node]
    while stack:
        item = stack.pop()
        if item.type == "comment":
            continue
        if item.type == "parenthesized_expression":
            children = [child for child in item.named_children if child.type != "comment"]
            if len(children) == 1:
                stack.append(children[0])
            else:
                yield item
        elif item.type in {"assignment_pattern", "object_assignment_pattern", "pair_pattern"}:
            target = item.child_by_field_name("value" if item.type == "pair_pattern" else "left")
            if target is not None:
                stack.append(target)
            else:
                yield item
        elif item.type in {"array_pattern", "object_pattern", "rest_pattern"}:
            stack.extend(reversed(item.named_children))
        else:
            yield item


def _container(node: Node) -> int | None:
    """같은 program/block의 직선 문장만 별칭 순서 근거로 사용한다."""
    current = node
    while current.parent is not None:
        parent = current.parent
        if parent.type in {"program", "statement_block"}: return parent.id
        if parent.type not in {"expression_statement", "lexical_declaration", "variable_declaration",
                               "variable_declarator", "return_statement", "arguments", "call_expression",
                               "parenthesized_expression", "await_expression"}: return None
        current = parent
    return None


def analyze_javascript(source: bytes, file_label: str = "input.js", *,
                       limits: AnalysisLimits = AnalysisLimits(),
                       _clock: Callable[[], float] = time.monotonic) -> AnalysisResult:
    """호출자가 제공한 제한된 바이트만 읽는다. 원문·이름·절대 경로는 결과에 넣지 않는다."""
    valid_label = (isinstance(file_label, str) and len(file_label) <= 240
                   and re.fullmatch(r"[A-Za-z0-9_./-]+", file_label) is not None
                   and not file_label.startswith("/") and all(part not in {"", ".", ".."} for part in file_label.split("/")))
    if not valid_label or type(source) is not bytes:
        return AnalysisResult(AnalysisStatus.INVALID_INPUT, file_label if valid_label else None,
                              diagnostics=(Diagnostic(DiagnosticCode.INVALID_INPUT),))
    if len(source) > limits.max_bytes:
        return AnalysisResult(AnalysisStatus.RESOURCE_LIMIT, file_label, diagnostics=(Diagnostic(DiagnosticCode.RESOURCE_LIMIT),))
    if b"\x00" in source:
        return AnalysisResult(AnalysisStatus.INVALID_INPUT, file_label, diagnostics=(Diagnostic(DiagnosticCode.INVALID_INPUT),))
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return AnalysisResult(AnalysisStatus.INVALID_INPUT, file_label, diagnostics=(Diagnostic(DiagnosticCode.INVALID_INPUT),))
    deadline = _clock() + limits.max_seconds
    cancelled = False

    def expired(*_args):
        nonlocal cancelled
        cancelled = cancelled or _clock() >= deadline
        return cancelled

    def check():
        if expired(): raise _BudgetExceeded

    def read(offset, _point):
        return b"" if expired() else source[offset:offset + 4096]

    def name(node):
        return source[node.start_byte:node.end_byte].decode("utf-8")

    try:
        parser = Parser(Language(tree_sitter_javascript.language()))
        # 고정된 0.26.0/Python 3.12에서 progress_callback 경로가 충돌해 사용하지 않는다.
        # 읽기·순회 시 협력적으로 중단하며 네이티브 강제 실행 시간 상한은 주장하지 않는다.
        tree = parser.parse(read)
        check()
        if tree is None: raise ValueError("parser_unavailable")
        if tree.root_node.has_error:
            return AnalysisResult(AnalysisStatus.PARSE_ERROR, file_label, diagnostics=(Diagnostic(DiagnosticCode.PARSE_ERROR),))
        nodes: list[Node] = []
        stack = [(tree.root_node, 0)]
        while stack:
            check()
            node, depth = stack.pop()
            if depth > limits.max_depth or len(nodes) >= limits.max_nodes: raise _BudgetExceeded
            nodes.append(node)
            stack.extend((child, depth + 1) for child in reversed(node.named_children))

        scopes: list[_Scope] = []
        node_scope: dict[int, int] = {}
        diagnostics: list[Diagnostic] = []
        observations: list[EvalObservation] = []
        partial = False
        barrier = False
        excluded: list[Node] = []

        def diagnose(code, node=None, *, incomplete=True):
            nonlocal partial
            check()
            if len(diagnostics) >= limits.max_diagnostics: raise _BudgetExceeded
            diagnostics.append(Diagnostic(code, _span(node) if node else None))
            partial = partial or incomplete

        def add(scope, pattern, declaration, kind, value=None):
            for identifier in _pattern_names(pattern):
                check()
                scopes[scope].bindings.setdefault(name(identifier), []).append(_Binding(declaration, pattern, scope, kind, value))

        def function_scope(scope):
            while scopes[scope].parent is not None and scopes[scope].node.type not in _FUNCTIONS:
                scope = scopes[scope].parent
            return scope

        def resolve(scope, identifier):
            while True:
                check()
                if identifier in scopes[scope].bindings: return scopes[scope].bindings[identifier]
                parent = scopes[scope].parent
                if parent is None: return []
                scope = parent

        for node in nodes:
            check()
            parent_scope = node_scope.get(node.parent.id) if node.parent else None
            if node.type in _FUNCTION_DECLS and parent_scope is not None:
                add(parent_scope, node.child_by_field_name("name"), node, "function")
                parent = node.parent
                if parent.type != "program" and not (parent.type == "statement_block" and parent.parent and parent.parent.type in _FUNCTIONS):
                    target = function_scope(parent_scope)
                    if target != parent_scope: add(target, node.child_by_field_name("name"), node, "ambiguous")
                    diagnose(DiagnosticCode.ANNEX_B_BINDING, node)
            if node.type == "class_declaration" and parent_scope is not None:
                add(parent_scope, node.child_by_field_name("name"), node, "class")
            if parent_scope is None or node.type in _FUNCTIONS | _SCOPES:
                scope = len(scopes)
                unit = scope if parent_scope is None or node.type in _FUNCTIONS else scopes[parent_scope].unit
                scopes.append(_Scope(node, parent_scope, unit))
            else: scope = parent_scope
            node_scope[node.id] = scope
            if node.type in _FUNCTIONS:
                parameters = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
                add(scope, parameters, node, "parameter")
                if parameters and parameters.type == "formal_parameters" and any(child.type != "identifier" for child in parameters.named_children):
                    excluded.append(parameters)
                    diagnose(DiagnosticCode.UNSUPPORTED_CONSTRUCT, parameters)
                if node.type not in _FUNCTION_DECLS and node.type != "method_definition":
                    add(scope, node.child_by_field_name("name"), node, "function")
            if node.type == "catch_clause": add(scope, node.child_by_field_name("parameter"), node, "parameter")
            if node.type in {"class_declaration", "class"}:
                add(scope, node.child_by_field_name("name"), node, "class")
                excluded.append(node)
                diagnose(DiagnosticCode.UNSUPPORTED_CONSTRUCT, node)
            if node.type.startswith("jsx_") and not (node.parent and node.parent.type.startswith("jsx_")):
                excluded.append(node)
                diagnose(DiagnosticCode.UNSUPPORTED_CONSTRUCT, node)
            if node.type in {"identifier", "property_identifier", "shorthand_property_identifier_pattern"} and "\\" in name(node):
                barrier = True
                diagnose(DiagnosticCode.ESCAPED_IDENTIFIER, node)
            if node.type == "with_statement":
                barrier = True
                diagnose(DiagnosticCode.DYNAMIC_BINDING, node)
            if node.type == "variable_declarator":
                target = function_scope(scope) if node.parent.type == "variable_declaration" else scope
                add(target, node.child_by_field_name("name"), node, "variable", node.child_by_field_name("value"))
            if node.type == "for_in_statement":
                kind = next((child.type for child in node.children if child.type in {"var", "let", "const"}), None)
                if kind: add(function_scope(scope) if kind == "var" else scope, node.child_by_field_name("left"), node, "loop")
            if node.type == "import_specifier":
                add(scope, node.child_by_field_name("alias") or node.child_by_field_name("name"), node, "import")
            if node.type in {"import_clause", "namespace_import"}:
                for child in node.named_children:
                    if child.type == "identifier": add(scope, child, node, "import")

        # 모든 선언을 먼저 수집해 hoisting/TDZ 및 나중에 나타난 shadowing도 보수적으로 반영한다.
        for node in nodes:
            check()
            left = None
            if node.type in {"assignment_expression", "augmented_assignment_expression"}: left = node.child_by_field_name("left")
            elif node.type == "update_expression": left = node.child_by_field_name("argument")
            elif node.type == "for_in_statement" and not any(child.type in {"var", "let", "const"} for child in node.children): left = node.child_by_field_name("left")
            elif node.type == "unary_expression" and any(child.type == "delete" for child in node.children): left = node.child_by_field_name("argument")
            if left:
                for target in _write_targets(left):
                    check()
                    if target.type in {"identifier", "shorthand_property_identifier_pattern"}:
                        bindings = resolve(node_scope[node.id], name(target))
                        for binding in bindings: binding.written = True
                        if not bindings and name(target) == "eval":
                            barrier = True
                            diagnose(DiagnosticCode.DYNAMIC_BINDING, node)
                    elif target.type in {"member_expression", "subscript_expression"}:
                        barrier = True
                        diagnose(DiagnosticCode.DYNAMIC_BINDING, node)
                    else:
                        barrier = True
                        diagnose(DiagnosticCode.UNSUPPORTED_CONSTRUCT, target)

        for node in nodes:
            check()
            if node.type == "new_expression": diagnose(DiagnosticCode.UNSUPPORTED_CONSTRUCT, node)
            if node.type != "call_expression" or barrier: continue
            if any(item.start_byte <= node.start_byte < item.end_byte for item in excluded): continue
            callee = node.child_by_field_name("function")
            if callee is None: continue
            arguments = node.child_by_field_name("arguments")
            if callee.type != "identifier" or node.child_by_field_name("optional_chain") is not None or arguments is None or arguments.type != "arguments":
                diagnose(DiagnosticCode.UNSUPPORTED_CALLEE, node)
                continue
            scope = node_scope[node.id]
            bindings = resolve(scope, name(callee))
            unit = scopes[scopes[scope].unit].node
            if name(callee) == "eval":
                if bindings:
                    diagnose(DiagnosticCode.LOCAL_EVAL_SHADOW, callee, incomplete=False)
                    continue
                observation = EvalObservation("DIRECT_CALL", _span(node), _span(callee), _span(unit), eval_reference=_span(callee))
            else:
                if len(bindings) != 1:
                    diagnose(DiagnosticCode.AMBIGUOUS_BINDING if bindings else DiagnosticCode.UNRESOLVED_CALL, callee)
                    continue
                binding = bindings[0]
                value = binding.value
                if binding.kind != "variable" or binding.pattern.type != "identifier" or value is None or value.type != "identifier" or name(value) != "eval":
                    diagnose(DiagnosticCode.UNRESOLVED_CALL, callee)
                    continue
                if resolve(node_scope[value.id], "eval"):
                    diagnose(DiagnosticCode.LOCAL_EVAL_SHADOW, value, incomplete=False)
                    continue
                if binding.written:
                    diagnose(DiagnosticCode.BINDING_REASSIGNED, callee)
                    continue
                if scopes[binding.scope].unit != scopes[scope].unit:
                    diagnose(DiagnosticCode.CROSS_FUNCTION_ALIAS, callee)
                    continue
                container = _container(binding.declaration)
                if container is None or container != _container(node) or binding.declaration.end_byte > node.start_byte:
                    diagnose(DiagnosticCode.ALIAS_ORDER_OR_CONTROL_FLOW, callee)
                    continue
                observation = EvalObservation("SIMPLE_ALIAS_CALL", _span(node), _span(callee), _span(unit), _span(binding.declaration), _span(value))
            if len(observations) >= limits.max_observations: raise _BudgetExceeded
            observations.append(observation)
        check()
        return AnalysisResult(AnalysisStatus.PARTIAL if partial else AnalysisStatus.ANALYZED, file_label,
                              tuple(observations), tuple(diagnostics))
    except _BudgetExceeded:
        return AnalysisResult(AnalysisStatus.RESOURCE_LIMIT, file_label, diagnostics=(Diagnostic(DiagnosticCode.RESOURCE_LIMIT),))
    except Exception:
        # 네이티브 오류 내용이나 원문을 외부 결과로 복사하지 않는다.
        return AnalysisResult(AnalysisStatus.RESOURCE_LIMIT if cancelled else AnalysisStatus.UNAVAILABLE, file_label,
                              diagnostics=(Diagnostic(DiagnosticCode.RESOURCE_LIMIT if cancelled else DiagnosticCode.PARSER_UNAVAILABLE),))
