export function previewAdministratorRule(input) {
  const compile = new Function("context", input.ruleText);
  return compile(input.context);
}
