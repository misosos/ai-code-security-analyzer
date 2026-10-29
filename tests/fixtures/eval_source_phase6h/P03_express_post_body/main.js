import express from "express";
const app = express();
app.post("/run", (req, res) => eval(req.body.code));
