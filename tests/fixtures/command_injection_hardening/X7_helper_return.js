const child_process = require("child_process");
function commandFor(req) {
  return req.query.cmd;
}
function handler(req) {
  child_process.exec(commandFor(req));
}
