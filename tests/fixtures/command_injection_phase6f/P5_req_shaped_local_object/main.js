const cp = require("child_process");
const req = { query: { cmd: readLocalPreference() } };
export function run() {
  return cp.exec(req.query.cmd);
}
