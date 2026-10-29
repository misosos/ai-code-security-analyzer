export function readFilter(req) {
  return JSON.parse(req.query.filter);
}
