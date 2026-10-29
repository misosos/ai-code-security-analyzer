const { spawn } = require("node:child_process");
export function run(req, options) {
  return spawn("tool", [req.query.cmd], options);
}
