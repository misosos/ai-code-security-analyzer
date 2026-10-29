import express from "express";
const app = express();
app.get("/alias", (req, res) => {
  const expression = req.query.code;
  eval(expression);
});
