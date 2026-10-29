function run(mockProcess, req) {
  return mockProcess.exec(req.body.cmd);
}
