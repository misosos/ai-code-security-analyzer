const child_process = require("child_process");
function handler(req) {
  let command = "status";
  command = req.query.cmd;
  child_process.exec(command);
}
