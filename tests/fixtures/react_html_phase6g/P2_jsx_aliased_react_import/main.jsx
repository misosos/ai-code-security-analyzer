import UI from "react";
const markup = { __html: getNotice() };
export const Notice = () => <div dangerouslySetInnerHTML={markup} />;
