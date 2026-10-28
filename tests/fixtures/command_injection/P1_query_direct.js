const child_process = require("child_process");
function handler(req) {
  child_process.exec(req.query.cmd);
}
