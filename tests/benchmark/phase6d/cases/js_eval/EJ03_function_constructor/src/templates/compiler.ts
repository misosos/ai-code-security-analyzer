export function compile(source: string) {
  return new Function("record", source);
}
