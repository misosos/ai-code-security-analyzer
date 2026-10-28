const child_process = require("child_process");
function handler(req) {
  const first = req.body.cmd;
  const second = first;
  child_process.exec(second);
}
