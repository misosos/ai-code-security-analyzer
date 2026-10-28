import { exec } from "node:child_process";
export function handler(req: { query: { cmd: string } }) {
  exec(req.query.cmd);
}
