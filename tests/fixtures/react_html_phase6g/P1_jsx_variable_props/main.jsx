import React from "react";
// PHASE6G_SYNTHETIC_REACT_CANARY
const markup = { __html: readBannerContent() };
export function Banner() {
  return <section dangerouslySetInnerHTML={markup} />;
}
