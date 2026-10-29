const cp = require("child_process");
export function launch(req) { return cp.exec("echo " + req.body.cmd); }
