export function execute(request: Request) {
  const input = request.query.expression;
  return eval(input);
}
