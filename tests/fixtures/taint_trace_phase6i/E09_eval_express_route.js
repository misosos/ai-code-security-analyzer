import express from "express";
const app = express();
app.post("/preview", (request, response) => {
  eval(request.body.code);
});
