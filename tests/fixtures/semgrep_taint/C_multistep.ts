function handle(req: { query: { code: string } }) {
  const first = req.query.code;
  const second = first;
  const third = second;
  eval(third);
}
