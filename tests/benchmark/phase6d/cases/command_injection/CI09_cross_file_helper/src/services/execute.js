const child_process = require("child_process");
export function execute(command) {
  child_process.exec(command);
}
