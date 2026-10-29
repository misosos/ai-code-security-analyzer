export function preview(req) {
  return eval(req.query.code);
}
