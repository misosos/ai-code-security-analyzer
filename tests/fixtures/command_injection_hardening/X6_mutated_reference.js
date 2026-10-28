let child_process = require("child_process");
function handler(req, alternate) {
  child_process = alternate;
  child_process.exec(req.query.cmd);
}
