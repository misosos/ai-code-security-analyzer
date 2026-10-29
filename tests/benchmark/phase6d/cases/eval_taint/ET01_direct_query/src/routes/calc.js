export function calculate(req) {
  return eval(req.query.code);
}
