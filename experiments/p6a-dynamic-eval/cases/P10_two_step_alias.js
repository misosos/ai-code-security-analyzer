// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  const builtin = globalThis.eval;
  const eval = builtin;
  return eval(code);
}
