import { exec } from "child_process";
export function handler(req: { body: { cmd: string } }) {
  exec(req.body.cmd);
}
