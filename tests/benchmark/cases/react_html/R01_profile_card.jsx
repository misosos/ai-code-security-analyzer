export function ProfileCard({ displayName }) {
  return <section dangerouslySetInnerHTML={{ __html: displayName }} />;
}
