export function execute(request: Request) {
  const input = request.query.expression ?? "";
  const checked = validateExpression(input);
  return eval(checked);
}
