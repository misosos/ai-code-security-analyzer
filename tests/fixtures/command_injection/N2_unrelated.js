const child_process = require("child_process");
function handler(req, configuredCommand) {
  child_process.exec(configuredCommand);
}
