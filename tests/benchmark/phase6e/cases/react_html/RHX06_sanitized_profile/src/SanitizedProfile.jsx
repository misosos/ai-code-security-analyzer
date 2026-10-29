export function SanitizedProfile({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: sanitize(html) }} />;
}
