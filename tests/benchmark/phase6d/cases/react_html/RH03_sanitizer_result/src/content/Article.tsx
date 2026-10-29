export function Article({ raw }: { raw: string }) {
  const cleaned = sanitizeMarkup(raw);
  return <article dangerouslySetInnerHTML={{ __html: cleaned }} />;
}
