function run(req) {
  eval(req.query.code);
  eval(req.body.code);
}
