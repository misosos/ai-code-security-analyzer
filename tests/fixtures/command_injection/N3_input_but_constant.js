const child_process = require("child_process");
function handler(req) {
  const ignored = req.query.cmd;
  child_process.exec("status");
}
