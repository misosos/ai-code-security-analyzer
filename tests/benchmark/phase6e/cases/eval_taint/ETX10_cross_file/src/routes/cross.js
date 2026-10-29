import { evaluate } from "../lib/evaluate.js";
export function route(req) { return evaluate(req.body.code); }
