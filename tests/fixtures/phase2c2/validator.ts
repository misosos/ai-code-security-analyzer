export function validateExpression(value: string) {
  return /^\d+$/.test(value) ? value : "0";
}
