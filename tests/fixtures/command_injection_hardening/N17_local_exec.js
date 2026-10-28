function exec(command) {
  return command;
}
function handler(req) {
  exec(req.query.cmd);
}
