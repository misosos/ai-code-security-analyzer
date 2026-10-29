import { evaluate } from "../services/evaluate.js";
export function route(req) {
  return evaluate(req.query.code);
}
