export function Profile({ bio }) {
  return <section dangerouslySetInnerHTML={{ __html: bio }} />;
}
