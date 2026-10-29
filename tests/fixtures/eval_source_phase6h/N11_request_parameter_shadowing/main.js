import express from "express";
const app = express();
app.get("/shadow", (req, res) => {
  function offline(req) { return eval(req.query.code); }
});
