const child_process = require("child_process");
function handler(req) {
  const child_process = { exec: (value) => value };
  child_process.exec(req.query.cmd);
}
