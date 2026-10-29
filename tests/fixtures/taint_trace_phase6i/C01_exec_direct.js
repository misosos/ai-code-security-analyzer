const cp = require("child_process");
function run(req) {
  cp.exec(req.query.cmd);
}
