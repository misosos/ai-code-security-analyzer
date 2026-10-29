export function Widget({ html }: { html: string }) {
  return <div dangerouslySetInnerHTMLX={{ __html: html }} />;
}
