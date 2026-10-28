import { exec } from "some-other-package";
export function handler(req: { query: { cmd: string } }) {
  exec(req.query.cmd);
}
