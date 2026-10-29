const express = require("express");
const app = express();

app.post("/preview", (request, response) => {
  const expression = request.body.code;
  response.send(eval(expression));
});
