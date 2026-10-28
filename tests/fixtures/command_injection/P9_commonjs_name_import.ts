import * as child_process from "child_process";
export function handler(req: { query: { cmd: string } }) {
  child_process.exec(req.query.cmd);
}
