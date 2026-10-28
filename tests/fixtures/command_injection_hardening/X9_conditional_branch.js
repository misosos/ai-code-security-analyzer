const child_process = require("child_process");
function handler(req, condition) {
  let command = "status";
  if (condition) command = req.query.cmd;
  child_process.exec(command);
}
