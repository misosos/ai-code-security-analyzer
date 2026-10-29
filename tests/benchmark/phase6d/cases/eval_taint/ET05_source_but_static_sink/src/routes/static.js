export function render(req) {
  const supplied = req.query.code;
  audit(supplied);
  return eval("1 + 1");
}
