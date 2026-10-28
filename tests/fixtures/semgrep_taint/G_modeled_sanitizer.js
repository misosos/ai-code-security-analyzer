function handle(req) {
  const checked = syntheticSafe(req.query.code);
  eval(checked);
}
