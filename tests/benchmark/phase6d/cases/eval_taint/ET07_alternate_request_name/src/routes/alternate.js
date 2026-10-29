export function run(request) {
  return eval(request.body.code);
}
