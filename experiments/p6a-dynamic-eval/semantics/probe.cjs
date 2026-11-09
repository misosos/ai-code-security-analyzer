// Synthetic semantics probe. Evaluates only the fixed string "secret".
// "local" => direct eval (sees the caller's scope). Indirect eval sees only the global scope; in CommonJS the
// top-level `var secret` is module-scoped, so indirect eval throws "secret is not defined".
var secret = 'global-only';
function report(name, fn) {
  try { console.log(name.padEnd(34), '->', fn()); }
  catch (e) { console.log(name.padEnd(34), '->', `${e.constructor.name}: ${e.message}`); }
}
report('S1 eval(x)',                   () => { var secret = 'local'; return eval('secret'); });
report('S2 (0, eval)(x)',              () => { var secret = 'local'; return (0, eval)('secret'); });
report('S3 const run = eval; run(x)',  () => { var secret = 'local'; const run = eval; return run('secret'); });
report('S4 globalThis.eval(x)',        () => { var secret = 'local'; return globalThis.eval('secret'); });
report('S5 const eval = globalThis.eval', () => { var secret = 'local'; const eval = globalThis.eval; return eval('secret'); });
report('S6 let eval = globalThis.eval',   () => { var secret = 'local'; let eval = globalThis.eval; return eval('secret'); });
report('S7 const eval = JSON.parse',   () => { var secret = 'local'; const eval = JSON.parse; return eval('"parsed"'); });
report('S8 eval param holding %eval%', () => { var secret = 'local'; return ((eval) => eval('secret'))(globalThis.eval); });
report('S9 const eval = eval (TDZ)',   () => { var secret = 'local'; const eval = eval; return eval('secret'); });
report('S10 const {eval} = globalThis',() => { var secret = 'local'; const { eval } = globalThis; return eval('secret'); });
report('S11 globalThis.eval replaced', () => { var secret = 'local'; const original = globalThis.eval; globalThis.eval = JSON.parse; try { const eval = globalThis.eval; return eval('"replaced"'); } finally { globalThis.eval = original; } });
