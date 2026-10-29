const child_process = require("child_process");
export function run() {
  child_process.execSync("refresh-local-index");
}
