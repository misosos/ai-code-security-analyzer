export function UnsafeMarkup({ html }: { html: string }) {
  return <div className="content" dangerouslySetInnerHTML={{ __html: html }} />;
}
