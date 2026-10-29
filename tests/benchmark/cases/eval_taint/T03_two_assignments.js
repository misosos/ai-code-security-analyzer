function compile(req) {
  const incoming = req.query.code;
  const programText = incoming;
  return eval(programText);
}
