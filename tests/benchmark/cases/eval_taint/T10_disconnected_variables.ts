function evaluate(req: { query: { code: string } }, localText: string) {
  const ignored = req.query.code;
  return eval(localText);
}
