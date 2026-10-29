import express from "express";
const app = express();
app.get("/param", (req, res) => {
  eval(req.params.code);
});
