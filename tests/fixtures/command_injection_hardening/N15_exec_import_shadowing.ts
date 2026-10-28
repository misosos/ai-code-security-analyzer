import { exec } from "child_process";
export function handler(req: { query: { cmd: string } }) {
  const exec = (value: string) => value;
  exec(req.query.cmd);
}
