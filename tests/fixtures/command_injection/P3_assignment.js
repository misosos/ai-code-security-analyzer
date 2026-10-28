const child_process = require("child_process");
function handler(req) {
  const command = req.query.cmd;
  child_process.exec(command);
}
