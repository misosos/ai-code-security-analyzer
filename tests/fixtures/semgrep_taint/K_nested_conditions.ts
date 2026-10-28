type RequestLike = { body: { code: string } };

function handle(req: RequestLike) {
  const code: string = req.body.code;
  if (code.length > 0) {
    if (isAllowed(code)) {
      const forwarded: string = code;
      eval(forwarded);
    }
  }
}
