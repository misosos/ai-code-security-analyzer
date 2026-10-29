import express from "express";
const app = express();
app.get("/static", (req, res) => {
  const ignored = req.query.code;
  eval("static_expression");
});
