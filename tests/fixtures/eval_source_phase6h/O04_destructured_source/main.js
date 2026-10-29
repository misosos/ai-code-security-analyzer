import express from "express";
const app = express();
app.post("/destructure", (req, res) => {
  const { code } = req.body;
  eval(code);
});
