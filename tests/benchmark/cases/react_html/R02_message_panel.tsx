type Props = { markup: string };
export function MessagePanel({ markup }: Props) {
  return <article dangerouslySetInnerHTML={{ __html: markup }} />;
}
