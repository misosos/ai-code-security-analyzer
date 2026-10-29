export function createMapper(source) {
  return new Function("record", source);
}
