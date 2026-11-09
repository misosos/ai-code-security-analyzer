// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function run(code, useNative) {
  const eval = useNative ? globalThis.eval : JSON.parse;
  return eval(code);
}
