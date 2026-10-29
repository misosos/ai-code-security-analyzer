type Props = { html: string };
export function Message({ html }: Props) {
  return <section dangerouslySetInnerHTML={{ __html: html }} />;
}
