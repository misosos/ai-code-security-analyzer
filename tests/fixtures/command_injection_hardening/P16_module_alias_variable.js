const cp = require("child_process");
function handler(req) {
  const command = req.query.cmd;
  cp.exec(command);
}
