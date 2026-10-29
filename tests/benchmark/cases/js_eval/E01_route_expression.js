export function renderPreview(req) {
  const expression = req.body.expression;
  return eval(expression);
}
