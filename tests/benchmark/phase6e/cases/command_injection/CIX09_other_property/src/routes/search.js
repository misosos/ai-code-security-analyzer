const cp = require("child_process");
export function search(req) { return cp.exec(req.query.term); }
