import { spawn } from "node:child_process";
router.get("/search", (req, res) => {
  return spawn("tool", [req.query.term], { shell: true });
});
