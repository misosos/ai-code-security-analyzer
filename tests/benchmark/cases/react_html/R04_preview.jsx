export function Preview({ sanitizedPreview }) {
  return <main dangerouslySetInnerHTML={{ __html: sanitizedPreview }} />;
}
