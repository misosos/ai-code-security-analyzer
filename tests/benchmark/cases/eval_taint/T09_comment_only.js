function render(req) {
  // eval(req.query.code) was removed during migration.
  return String(req.query.code);
}
