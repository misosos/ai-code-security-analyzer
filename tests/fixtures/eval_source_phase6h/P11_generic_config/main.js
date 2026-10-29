export function render(config) {
  const script = config.query.code;
  return eval(script);
}
