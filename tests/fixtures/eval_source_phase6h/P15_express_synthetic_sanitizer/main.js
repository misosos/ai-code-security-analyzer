import express from "express";
const app = express();
app.post("/modeled", (req, res) => {
  eval(syntheticSafe(req.body.code));
});
