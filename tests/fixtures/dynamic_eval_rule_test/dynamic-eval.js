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

function functionShadow(input) {
  function eval(value) { return value; }
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

function methodNamedEval(policy, input) {
  // ok: baseline.javascript-dynamic-eval
  return policy.eval(input);
}

function safeParser(input) {
  // ok: baseline.javascript-dynamic-eval
  return JSON.parse(input);
}

// Known limitations, kept visible instead of hidden:
function capturedWrite(input) {
  let run = eval;
  function change() { run = JSON.parse; }
  // todoruleid: baseline.javascript-dynamic-eval
  return run(input);
}

function escapedShadow(eval, input) {
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
