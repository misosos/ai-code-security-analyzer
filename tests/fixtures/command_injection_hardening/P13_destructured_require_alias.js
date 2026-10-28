const { exec: runCommand } = require("node:child_process");
function handler(req) {
  runCommand(req.body.cmd);
}
