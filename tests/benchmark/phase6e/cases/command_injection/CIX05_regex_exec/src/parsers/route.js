export function parse(req) {
 return /^job-(.*)$/.exec(req.query.cmd);
}
