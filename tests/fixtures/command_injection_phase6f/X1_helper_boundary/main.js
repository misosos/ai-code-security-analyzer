import { spawn } from "node:child_process";
function dispatch(value) {
  return spawn("tool", [value], { shell: true });
}
export function run(req) {
  return dispatch(req.query.cmd);
}
