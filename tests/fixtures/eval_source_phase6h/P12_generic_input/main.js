export function compute(input) {
  const value = input.query.code;
  return eval(value);
}
