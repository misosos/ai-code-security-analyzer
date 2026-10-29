const child_process = require("child_process");
export function exportFile(req) {
 return child_process.exec("tar -cf /tmp/out " + req.query.cmd);
}
