export function execute(request: Request) {
  const input = request.query.expression ?? "0";
  if (!/^\d+$/.test(input)) {
    throw new Error("numeric expression required");
  }
  return eval(input);
}
