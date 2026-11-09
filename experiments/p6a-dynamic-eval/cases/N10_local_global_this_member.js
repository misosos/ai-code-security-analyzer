// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code) {
  const globalThis = { eval: (v) => v };
  return globalThis.eval(code);
}
