export function preview(req) {
  const expression = req.query.code;
  return eval(expression);
}
