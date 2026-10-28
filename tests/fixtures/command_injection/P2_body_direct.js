const child_process = require("node:child_process");
function handler(req) {
  child_process.exec(req.body.cmd);
}
