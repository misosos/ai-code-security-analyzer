// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function parse(text) {
  const eval = JSON.parse;
  return eval(text);
}
