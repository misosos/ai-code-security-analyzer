const child_process = require("child_process");
function run(req) {
  child_process.exec("fixed-task", { cwd: req.query.cmd });
}
