export function parse(req) {
  return parseExpression(req.body.code);
}
