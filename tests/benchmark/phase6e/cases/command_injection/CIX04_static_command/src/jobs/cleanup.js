const child_process = require("child_process");
export function cleanup() { return child_process.exec("rm -rf ./cache"); }
