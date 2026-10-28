function readCode(req) {
  return req.query.code;
}

function execute(code) {
  eval(code);
}

function handle(req) {
  execute(readCode(req));
}
