export function Preview({ draft }: { draft: string }) {
  const [html] = useState(draft);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
