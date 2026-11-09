// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  const { eval } = globalThis;
  return eval(code);
}
