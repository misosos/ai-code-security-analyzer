import { exec as runCommand } from "node:child_process";
export const archive = (req) => runCommand(`zip ${req.query.cmd}`);
