const { exec } = require("child_process");
function handler(req) {
  exec(req.query.cmd);
}
