export function expression(req) {
  return eval(req.query.expression);
}
