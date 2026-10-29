import { spawn } from "node:child_process";
export function run(req) { return spawn("tool", [req.query.cmd]); }
