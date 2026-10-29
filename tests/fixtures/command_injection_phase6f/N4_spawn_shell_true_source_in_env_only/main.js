const { spawn } = require("node:child_process");
export function run(req) {
  return spawn("tool", ["fixed"], { shell: true, env: { SEARCH: req.query.cmd } });
}
