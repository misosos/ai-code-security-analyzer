const cp = { spawn(command, args, options) { return command; } };
export function run(req) {
  return cp.spawn("tool", [req.query.cmd], { shell: true });
}
