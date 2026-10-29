const cp = require("child_process");
function run(req) {
  const observed = req.query.cmd;
  cp.exec("constant command");
}
