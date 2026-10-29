import { execute } from "../services/execute.js";
export function route(req) {
  return execute(req.query.cmd);
}
