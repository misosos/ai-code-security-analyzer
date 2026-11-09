// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  const evaluate = globalThis.eval;
  return evaluate(code);
}
