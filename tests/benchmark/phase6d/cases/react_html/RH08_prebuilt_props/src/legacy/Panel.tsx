export function Panel({ html }: { html: string }) {
  const props = { __html: html };
  return <div dangerouslySetInnerHTML={props} />;
}
