import express from "express";
const app = express();
app.get("/preview", (req, res) => {
  eval(req.query.code);
});
