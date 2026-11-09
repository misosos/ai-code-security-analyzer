// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(text) {
  const eval = globalThis.eval;
  {
    const eval = JSON.parse;
    return eval(text);
  }
}
