const child_process = require("child_process");
function handler(req, useQuery) {
  let command = "status";
  if (useQuery) {
    command = req.query.cmd;
  }
  child_process.exec(command);
}
