const child_process = require("child_process");
function handler(req) {
  const ignored = req.query.cmd;
  const command = "status";
  child_process.exec(command);
}
