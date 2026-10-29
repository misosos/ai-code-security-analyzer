const cp = require("child_process");
export function cleanup() {
  cp.exec("rotate-cache");
}
