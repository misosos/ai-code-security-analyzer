// P6-A synthetic static-analysis case. Classic sloppy script; never executed.
function echo(value) {
  const eval = (v) => v;
  return eval(value);
}
