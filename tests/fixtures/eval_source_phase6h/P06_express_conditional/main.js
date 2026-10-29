import express from "express";
const app = express();
app.post("/conditional", (req, res) => {
  if (req.body.enabled) {
    eval(req.body.code);
  }
});
