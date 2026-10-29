import { spawn as launch } from "node:child_process";
export function run(req) {
  return launch("tool " + req.query.cmd, { shell: true });
}
