import React from "react";
export function Panel(html) {
  return React.createElement("div", { dangerouslySetInnerHTML: { __html: html } });
}
