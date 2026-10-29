import React from "react";
function makeProps(html) { return { dangerouslySetInnerHTML: { __html: html } }; }
export const Panel = (html) => React.createElement("div", makeProps(html));
