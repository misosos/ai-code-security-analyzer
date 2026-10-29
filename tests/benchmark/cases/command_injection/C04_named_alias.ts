import { exec as runCommand } from "node:child_process";
export function run(req: { query: { cmd: string } }) {
  runCommand(`task ${req.query.cmd}`);
}
