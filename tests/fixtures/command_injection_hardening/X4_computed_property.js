const child_process = require("child_process");
function handler(req, method) {
  child_process[method](req.query.cmd);
}
