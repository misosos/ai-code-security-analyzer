import React from "react";
export function render(React, html) {
  return React.createElement("div", { dangerouslySetInnerHTML: { __html: html } });
}
