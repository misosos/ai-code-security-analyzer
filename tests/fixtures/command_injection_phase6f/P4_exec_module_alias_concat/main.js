const cp = require("child_process");
export function run(req) {
  return cp.exec("echo " + req.body.cmd);
}
