import * as cp from "node:child_process";
function handler(req) {
  cp.exec(req.query.cmd);
}
