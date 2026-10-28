const child_process = require("child_process");
import { getCommand } from "./X2_interfile_source";
function handler(req) {
  child_process.exec(getCommand(req));
}
