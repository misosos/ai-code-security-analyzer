import { spawn } from "node:child_process";
function run(req) {
  spawn("tool", [req.query.cmd], { shell: false });
}
