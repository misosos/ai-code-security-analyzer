export function expression(req) {
  const value = req.query.expression;
  return eval(value);
}
