const child_process = require("child_process");
function handler(req) {
  const command = "status";
  child_process.exec(command);
  return req.query.cmd;
}
