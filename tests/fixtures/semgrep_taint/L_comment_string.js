function sample() {
  // eval(req.query.code)
  const example = "eval(req.query.code) // SYNTHETIC_TAINT_CANARY_ONLY";
  return example;
}
