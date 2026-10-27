export function execute(input: string) {
  if (!/^\d+$/.test(input)) { throw new Error("digits only"); }
  return eval(input);
}
