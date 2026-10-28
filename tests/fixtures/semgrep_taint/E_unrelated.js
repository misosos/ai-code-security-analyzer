function handle(req) {
  const supplied = req.query.code;
  const fixed = "2 + 2";
  eval(fixed);
  return supplied;
}
