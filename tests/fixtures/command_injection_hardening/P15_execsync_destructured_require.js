const { execSync } = require("child_process");
function handler(req) {
  execSync(req.body.cmd);
}
