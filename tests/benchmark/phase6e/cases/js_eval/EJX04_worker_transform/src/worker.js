function transform(sourceText) {
  return Function(sourceText)();
}
