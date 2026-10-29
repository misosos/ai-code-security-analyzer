export function demo(req) {
  return eval(syntheticSafe(req.body.code));
}
