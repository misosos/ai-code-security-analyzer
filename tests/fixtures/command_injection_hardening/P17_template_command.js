const cp = require("child_process");
function handler(req) {
  cp.exec(`tool ${req.query.cmd}`);
}
