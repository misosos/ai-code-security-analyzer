function run(req) {
  const source = req.query.code || req.body.code;
  return eval(source);
}
