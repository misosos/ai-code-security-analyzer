export function execute(req) {
 const clean = normalize(req.query.code);
 return eval(clean);
}
