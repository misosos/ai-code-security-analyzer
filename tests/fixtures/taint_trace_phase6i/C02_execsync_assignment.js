const cp = require("node:child_process");
function run(req) {
  const command = req.body.cmd;
  cp.execSync(command);
}
