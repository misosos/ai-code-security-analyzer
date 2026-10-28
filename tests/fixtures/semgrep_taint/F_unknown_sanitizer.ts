function handle(req: { body: { code: string } }) {
  const checked = unknownValidate(req.body.code);
  eval(checked);
}
