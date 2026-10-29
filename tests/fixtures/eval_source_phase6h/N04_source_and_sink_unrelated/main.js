import express from "express";
const app = express();
app.post("/unrelated", (req, res) => {
  const value = req.body.code;
  eval(req.params.expression);
});
