function executeSnippet(snippet) {
  if (!snippet) return null;
  const result = eval(snippet);
  return result;
}
