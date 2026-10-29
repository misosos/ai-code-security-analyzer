import { spawn } from "some-package";
export function run(req) {
  return spawn("tool", [req.query.cmd], { shell: true });
}
