const express = require("express");
const app = express();
app.get("/legacy", (req, res) => {
  eval(req.query.code);
});
