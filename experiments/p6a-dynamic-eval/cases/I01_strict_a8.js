// P6-A-R synthetic static-analysis case. Strict script: an `eval` binding is a SyntaxError.
'use strict';
function run(code) {
  const eval = globalThis.eval;
  return eval(code);
}
