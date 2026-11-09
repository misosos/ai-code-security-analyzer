// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(input) {
  const window = { eval: (v) => v };
  return window.eval(input);
}
