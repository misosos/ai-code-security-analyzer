const child_process = require("child_process");
function handler(req, callback) {
  child_process.exec("status", req.query.cmd, callback);
}
