export function run(req) {
 const code = syntheticSafe(req.body.code);
 return eval(code);
}
