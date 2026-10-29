const React = { createElement: (tag, props) => props };
export const panel = (html) => React.createElement("div", { dangerouslySetInnerHTML: { __html: html } });
