export function Ticket({ html }) {
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
