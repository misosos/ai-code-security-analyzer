// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  const eval = window.eval;
  return eval(code);
}
