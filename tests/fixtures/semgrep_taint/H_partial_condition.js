function handle(req) {
  const code = req.query.code;
  if (code.length < 100) {
    eval(code);
  }
}
