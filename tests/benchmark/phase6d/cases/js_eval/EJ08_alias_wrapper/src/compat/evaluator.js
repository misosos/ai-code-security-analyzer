const dynamicEvaluator = eval;
export function run(expression) {
  return dynamicEvaluator(expression);
}
