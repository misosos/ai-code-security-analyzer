const child_process = require("child_process");
export function run(req) {
  child_process.exec("status", { shell: req.query.cmd });
}
