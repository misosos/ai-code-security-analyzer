export function run(req) {
  return dispatchCommand(req.body.cmd);
}
