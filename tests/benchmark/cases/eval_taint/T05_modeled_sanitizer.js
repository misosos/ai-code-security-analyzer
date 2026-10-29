function compile(req) {
  const source = req.body.code;
  return eval(syntheticSafe(source));
}
