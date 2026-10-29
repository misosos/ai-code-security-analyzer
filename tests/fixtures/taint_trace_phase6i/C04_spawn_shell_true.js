import { spawn } from "node:child_process";
function run(req) {
  spawn("sh", [req.query.cmd], { shell: true });
}
