import express from "express";
const router = express.Router();
router.get("/router", (req, res) => {
  eval(req.query.code);
});
