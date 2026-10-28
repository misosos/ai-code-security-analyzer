const child_process = require("child_process");
function handler(req) {
  const prefix = "tool";
  child_process.exec(`${prefix} ${req.query.cmd} --quiet`);
}
