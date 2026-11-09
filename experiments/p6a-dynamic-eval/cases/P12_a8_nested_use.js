// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  const eval = globalThis.eval;
  function inner() {
    return eval(code);
  }
  return inner();
}
