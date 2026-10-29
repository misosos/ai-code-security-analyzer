const { exec } = require("child_process");
function worker(req) {
  const commandText = req.body.cmd;
  exec(commandText);
}
