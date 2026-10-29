function inspect(req, pattern) {
  return pattern.exec(req.query.cmd);
}
