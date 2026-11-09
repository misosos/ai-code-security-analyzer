// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  let eval = globalThis.eval;
  return eval(code);
}
