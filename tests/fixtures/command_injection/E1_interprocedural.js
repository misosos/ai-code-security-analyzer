const child_process = require("child_process");
function execute(command) {
  child_process.exec(command);
}
function handler(req) {
  execute(req.query.cmd);
}
