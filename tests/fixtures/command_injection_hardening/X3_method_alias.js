const child_process = require("child_process");
function handler(req) {
  const run = child_process.exec;
  run(req.query.cmd);
}
