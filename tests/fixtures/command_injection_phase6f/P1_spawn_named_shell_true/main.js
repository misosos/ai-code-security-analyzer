import { spawn } from "node:child_process";
import express from "express";
const router = express.Router();
router.get("/run", (req, res) => {
  // PHASE6F_SYNTHETIC_CANARY
  return spawn("tool", [req.query.cmd], { shell: true });
});
