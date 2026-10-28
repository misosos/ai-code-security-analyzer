const cp = require("child_process");
function handler(req) {
  cp.exec(req.query.cmd);
}
