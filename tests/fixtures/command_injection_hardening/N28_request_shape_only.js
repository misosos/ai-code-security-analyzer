const child_process = require("child_process");
function handler(req) {
  const query = { cmd: "status" };
  child_process.exec(query.cmd);
}
