export function normalize(req) {
  return String(req.body.cmd).trim();
}
