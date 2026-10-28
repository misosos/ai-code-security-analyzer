function handler(req) {
  const syntheticMarker = "SYNTHETIC_COMMAND_INJECTION_CANARY_ONLY";
  return req.query.cmd;
}
