import express from "express";
const app = express();
app.get("/constant", (req, res) => {
  eval("2 + 2");
});
