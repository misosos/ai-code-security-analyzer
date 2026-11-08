// Semgrep native rule-test annotations for baseline.javascript-dynamic-eval.
// Synthetic static-analysis input only; never executed. Classic sloppy-mode
// script so shadowing bindings named eval are valid syntax.

function direct(input) {
  // ruleid: baseline.javascript-dynamic-eval
  return eval(input);
}

function constantArgument() {
  // ruleid: baseline.javascript-dynamic-eval
  return eval("6 * 7");
}

function constructorNew(source) {
  // ruleid: baseline.javascript-dynamic-eval
  return new Function("record", source);
}

function constructorCall(sourceText) {
  // ruleid: baseline.javascript-dynamic-eval
  return Function(sourceText)();
}

const compileText = Function;
function constructorAlias(body) {
  // ruleid: baseline.javascript-dynamic-eval
  return compileText(body);
}

function evalAlias(input) {
  const run = eval;
  // ruleid: baseline.javascript-dynamic-eval
  return run(input);
}

function commaIndirect(input) {
  // ruleid: baseline.javascript-dynamic-eval
  return (0, eval)(input);
}

function optionalCall(input) {
  // ruleid: baseline.javascript-dynamic-eval
  return eval?.(input);
}

function reassignedAlias(input) {
  let run = eval;
  run = JSON.parse;
  // ok: baseline.javascript-dynamic-eval
  return run(input);
}

function parameterShadow(eval, input) {
  // ok: baseline.javascript-dynamic-eval
  return eval(input);
}

function blockShadow(input) {
  {
    const eval = JSON.parse;
    // ok: baseline.javascript-dynamic-eval
    eval(input);
  }
  // ruleid: baseline.javascript-dynamic-eval
  return eval(input);
}

function functionParameterShadow(Function, body) {
  // ok: baseline.javascript-dynamic-eval
  return new Function(body);
}

function outerCallNotShadowed(code) {
  function inner(eval) { return eval; }
  // ruleid: baseline.javascript-dynamic-eval
  return eval(code);
}

// Nested-scope regressions (R1-P-R1): a binding inside a nested scope must not
// hide an outer global call, and an outer binding still covers nested calls.
function nestedHelperFunctionDeclaration(code) {
  function helper() { function eval(value) { return value; } return eval; }
  // ruleid: baseline.javascript-dynamic-eval
  return eval(code);
}

function nestedHelperConst(code) {
  function helper() { const eval = JSON.parse; return eval; }
  // ruleid: baseline.javascript-dynamic-eval
  return eval(code);
}

function nestedHelperLet(code) {
  function helper() { let eval = JSON.parse; return eval; }
  // ruleid: baseline.javascript-dynamic-eval
  return eval(code);
}

function nestedArrowParameter(code) {
  const helper = (eval) => eval;
  // ruleid: baseline.javascript-dynamic-eval
  return eval(code);
}

function nestedFunctionParameter(code) {
  function helper(Function) { return Function; }
  // ruleid: baseline.javascript-dynamic-eval
  return Function(code);
}

function outerAliasUsedInNestedFunction(code) {
  const run = eval;
  function inner() {
    // ruleid: baseline.javascript-dynamic-eval
    return run(code);
  }
  return inner;
}

function outerParameterSeenInNestedFunction(eval, code) {
  function inner() {
    // ok: baseline.javascript-dynamic-eval
    return eval(code);
  }
  return inner;
}

function outerConstSeenInNestedFunction(code) {
  const eval = JSON.parse;
  function inner() {
    // ok: baseline.javascript-dynamic-eval
    return eval(code);
  }
  return inner;
}

function outerFunctionParameterSeenInNestedFunction(Function, code) {
  function inner() {
    // ok: baseline.javascript-dynamic-eval
    return new Function(code);
  }
  return inner;
}

function innerAliasShadowsOuterAlias(code) {
  const run = eval;
  function inner() {
    const run = JSON.parse;
    // ok: baseline.javascript-dynamic-eval
    return run(code);
  }
  return inner;
}

function methodNamedEval(policy, input) {
  // ok: baseline.javascript-dynamic-eval
  return policy.eval(input);
}

function safeParser(input) {
  // ok: baseline.javascript-dynamic-eval
  return JSON.parse(input);
}

// Known limitations, kept visible instead of hidden:
// A block-level `function eval` (Annex B) is intentionally absent: sloppy
// scripts bind it in the function, strict code keeps the global.
function functionShadow(input) {
  function eval(value) { return value; }
  // todook: baseline.javascript-dynamic-eval
  return eval(input);
}

const arrowParameterShadow = (eval, input) =>
  // todook: baseline.javascript-dynamic-eval
  eval(input);

function capturedWrite(input) {
  let run = eval;
  function change() { run = JSON.parse; }
  // todoruleid: baseline.javascript-dynamic-eval
  return run(input);
}

function escapedShadow(\u0065val, input) {
  // todook: baseline.javascript-dynamic-eval
  return eval(input);
}

function varShadow(code) {
  var eval = function (value) { return value; };
  // todook: baseline.javascript-dynamic-eval
  return eval(code);
}

function globalMemberEval(code) {
  // todoruleid: baseline.javascript-dynamic-eval
  return globalThis.eval(code);
}

function reflectConstruct(body) {
  // todoruleid: baseline.javascript-dynamic-eval
  return Reflect.construct(Function, [body]);
}
