const { exec } = require("child_process");
export function inspect(req) { return exec("printf safe", { cwd: req.body.cmd }); }
