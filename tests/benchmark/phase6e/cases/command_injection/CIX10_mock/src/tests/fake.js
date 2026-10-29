const child_process = { exec(command) { return command.length; } };
export function test(req) { return child_process.exec(req.query.cmd); }
