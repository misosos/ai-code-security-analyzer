const HELP_MARKUP = "<p>Read the account guide.</p>";
export function HelpContent() {
  return <aside dangerouslySetInnerHTML={{ __html: HELP_MARKUP }} />;
}
