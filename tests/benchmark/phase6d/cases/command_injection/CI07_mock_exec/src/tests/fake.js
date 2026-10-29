const req = { query: { cmd: "synthetic" } };
const mock = { exec(command) { return command; } };
mock.exec(req.query.cmd);
