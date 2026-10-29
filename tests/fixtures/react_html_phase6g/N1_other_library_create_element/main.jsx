import UI from "other-library";
export const panel = (html) => UI.createElement("div", { dangerouslySetInnerHTML: { __html: html } });
