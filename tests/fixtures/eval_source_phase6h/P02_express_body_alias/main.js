import express from "express";
const app = express();
app.post("/calculate", (request, response) => {
  const input = request.body.code;
  eval(input);
});
