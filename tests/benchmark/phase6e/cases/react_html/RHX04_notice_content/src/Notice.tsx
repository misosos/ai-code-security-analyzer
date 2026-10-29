const markup = { __html: noticeText };
export const Notice = () => <div dangerouslySetInnerHTML={markup} />;
