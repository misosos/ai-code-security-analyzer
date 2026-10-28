function handle(req) {
  const code = req.body.code;
  eval(code);
}
