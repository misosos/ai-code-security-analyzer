export function evaluateBody(req: { body: { code: string } }) {
  const source = req.body.code;
  return eval(source);
}
