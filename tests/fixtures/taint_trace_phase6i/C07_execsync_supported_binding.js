function run(req) {
  require("child_process").execSync(req.body.cmd);
}
