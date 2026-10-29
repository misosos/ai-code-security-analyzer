const child_process = require("child_process");
export function run(request) {
  child_process.exec(request.query.cmd);
}
