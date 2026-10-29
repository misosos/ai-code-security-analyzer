import express from "express";
const app = express();
app.get("/value", (req, res) => {
  res.send(req.query.code);
});
