const cp = require("child_process");
export function run(req) {
  const argument = req.body.cmd;
  return cp.spawn("tool", [argument], { cwd: ".", shell: true });
}
