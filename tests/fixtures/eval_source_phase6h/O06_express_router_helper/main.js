import express from "express";
const router = express.Router();
router.post("/helper", (req, res) => {
  evaluate(req.body.code);
});
