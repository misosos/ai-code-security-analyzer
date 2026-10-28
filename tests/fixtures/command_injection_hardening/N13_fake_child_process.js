const child_process = { exec: (value) => value };
function handler(req) {
  child_process.exec(req.query.cmd);
}
