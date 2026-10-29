import express from "express";
const app = express();
app.get("/query", (request, response) => {
  eval(request.query.code);
});
