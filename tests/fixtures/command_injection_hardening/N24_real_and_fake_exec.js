const child_process = require("child_process");
function handler(req, mock) {
  child_process.exec("status");
  mock.exec(req.query.cmd);
}
