export function runExpression(input: string): unknown {
  return eval(input /* SYNTHETIC_BASELINE_SECRET */);
}

export function buildFunction(body: string): Function {
  return new Function("value", body);
}
