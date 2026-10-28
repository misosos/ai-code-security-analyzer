function handler(req) {
  const expression = /command/;
  expression.exec(req.query.cmd);
}
