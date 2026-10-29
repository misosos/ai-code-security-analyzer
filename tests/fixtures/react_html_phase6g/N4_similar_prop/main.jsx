import React from "react";
const markup = { __html: getHtml() };
export const Widget = () => <div data-dangerouslySetInnerHTML={markup} />;
