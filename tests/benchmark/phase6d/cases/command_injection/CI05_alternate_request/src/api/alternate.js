const cp = require("child_process");
export function run(request) {
  cp.exec(request.query.cmd);
}
