export function filterRows(req: { query: { code: string } }, rows: unknown[]) {
  return eval(req.query.code);
}
