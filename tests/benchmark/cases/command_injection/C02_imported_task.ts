import * as child_process from "node:child_process";
export function runTask(req: { body: { cmd: string } }) {
  child_process.execSync(req.body.cmd);
}
