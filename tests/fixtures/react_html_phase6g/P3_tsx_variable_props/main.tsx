import React from "react";
type Props = { html: string };
export const Card = ({ html }: Props) => {
  const markup = { __html: html };
  return <article dangerouslySetInnerHTML={markup} />;
};
