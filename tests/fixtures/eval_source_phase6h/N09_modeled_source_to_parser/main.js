import express from "express";
const app = express();
app.post("/parse", (req, res) => {
  return parseExpression(req.body.code);
});
