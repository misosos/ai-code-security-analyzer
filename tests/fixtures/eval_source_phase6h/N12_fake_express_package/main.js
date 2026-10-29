import express from "fake-express";
const app = express();
app.get("/fake", (req, res) => {
  eval(req.query.code);
});
