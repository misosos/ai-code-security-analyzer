import { exec as runCommand } from "node:child_process";
export function run(req: Request) {
  const command = req.query.cmd;
  runCommand(command);
}
