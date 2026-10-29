function evaluateRequest(req) {
  return eval(req.query.code);
}
