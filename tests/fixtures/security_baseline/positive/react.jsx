export function UnsafeMarkup({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
