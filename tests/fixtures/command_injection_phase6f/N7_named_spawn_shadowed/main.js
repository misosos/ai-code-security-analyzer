import { spawn } from "node:child_process";
export function run(req) {
  const spawn = mockSpawn;
  return spawn("tool", [req.query.cmd], { shell: true });
}
