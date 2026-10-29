import React from "react";
const markup = "not-an-html-props-object";
export const Incorrect = () => <div dangerouslySetInnerHTML={markup} />;
