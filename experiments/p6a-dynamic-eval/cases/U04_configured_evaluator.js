// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code, config) {
  const eval = config.evaluator;
  return eval(code);
}
