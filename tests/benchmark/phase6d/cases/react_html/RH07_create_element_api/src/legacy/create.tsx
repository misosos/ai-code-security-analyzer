export function renderMarkup(html: string) {
  return React.createElement("div", { dangerouslySetInnerHTML: { __html: html } });
}
