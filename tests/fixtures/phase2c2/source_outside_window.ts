export function execute(request: Request) {
  const query = new URLSearchParams(request.url.split("?")[1] ?? "");
  const candidate = query.get("expression") ?? "";
  const requestId = request.headers.get("x-request-id");
  const route = request.url.split("?")[0];
  const metricA = route.length;
  const metricB = requestId?.length ?? 0;
  const metricC = metricA + metricB;
  const metricD = metricC + 1;
  const metricE = metricD + 1;
  const metricF = metricE + 1;
  return eval(candidate);
}
