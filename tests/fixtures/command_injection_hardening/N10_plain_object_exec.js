function handler(req, service) {
  service.exec(req.query.cmd);
}
