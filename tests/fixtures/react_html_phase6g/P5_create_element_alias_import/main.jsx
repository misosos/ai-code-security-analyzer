import UI from "react";
export function Summary(html) {
  return UI.createElement("aside", { dangerouslySetInnerHTML: { __html: html } });
}
