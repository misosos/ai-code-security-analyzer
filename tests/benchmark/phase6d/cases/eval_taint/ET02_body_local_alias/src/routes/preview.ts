export function preview(req: Request) {
  const expression = req.body.code;
  return eval(expression);
}
