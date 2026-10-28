const child_process = require("child_process");
function handler(req, other) {
  const selected = req.query.cmd;
  child_process.exec(other.body.cmd);
}
