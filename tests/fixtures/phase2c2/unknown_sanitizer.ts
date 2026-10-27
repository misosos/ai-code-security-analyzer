export function execute(request: Request) {
  const input = request.body.expression;
  const checked = sanitizeForEvaluation(input);
  const requestType = request.headers.get("content-type");
  const auditTag = requestType ?? "unknown";
  return eval(checked);
}
