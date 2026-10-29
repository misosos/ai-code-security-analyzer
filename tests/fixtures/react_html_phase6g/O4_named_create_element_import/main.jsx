import { createElement as h } from "react";
export const Panel = (html) => h("div", { dangerouslySetInnerHTML: { __html: html } });
