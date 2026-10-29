import { exec as runCommand } from "node:child_process";
function run(req) {
  runCommand(req.query.cmd);
}
