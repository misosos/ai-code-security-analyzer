export function searchRoute(req) {
  const expression = req.query.expression;
  return eval(expression);
}
