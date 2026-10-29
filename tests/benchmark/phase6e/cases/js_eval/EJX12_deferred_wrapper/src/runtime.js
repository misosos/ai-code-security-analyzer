function buildRunner(text) { return makeRunner(text); }
function makeRunner(source) { return Function(source); }
