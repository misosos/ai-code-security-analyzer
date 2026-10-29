const { spawn } = require("child_process");
export function run(req) {
  return spawn("tool", [req.query.cmd], { shell: false });
}
