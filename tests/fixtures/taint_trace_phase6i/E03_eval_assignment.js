function run(req) {
  const source = req.query.code;
  return eval(source);
}
